function SyscallPredator {
<#
.DESCRIPTION
        Author: Silentis Vox (@SilentisVox)
        License: MIT License
        Required Dependencies: PowerShell 7+, .NET Trace Event Assembly
        Optional Dependencies: None

.SYNOPSIS
        This is a POC to Endpoint Detection & Response (EDR). Along with the documentation, this is
        an instrument to event parsing, but speciifically, tracking untrusted user space kernel mode
        transitions. This is known as a "direct syscall" where a user executes a syscall instruction
        in untrusted user space. This is an attempt to bypass userland hooks, if the EDR has enabled
        them.

        Technically, this tool tracks processes, threads, modules, and StackWalk events triggered by
        the SysExit event. If an associated process is being tracked, the StackWalk event is analyzed.
        If the first user space address lies within the originating process' image, this evidence is
        used to determine a direct syscall has taken place.

                                                '
                        ,                     .'
                      ,j;b_        ,        ,;' .,,'
                    .d;;:.Sb. .     ";     ,I:     .'
                   .d;;;:.Sb. .      ";    ,I :   ,.'
                 i d::::,$i. ;.,.;,,  .'i,.  $    ,
                d;;;:;:.,$7:. ..... ;.;,Ii '...''         .
               d;;;;;;;,$$":  .....;.;;I;; '', I.         ;
              ,;;;:;:.$$?,d .  .. ';, ';$,...,        .,'
              i;;:;;.$$7.d7 ;   "",,.';. ';;. ';..;$"''
              i;;;.$$?,;;; ;i$ ...;. I$ ; I.
              k;;.$$7.;%.' i;$ ...; .  ; ' ;' .
              ";;;$7.d?. .d;$' ...;.; ;;;;Ii;;;.
               "kiii,k. .d;$' ..;;.7  ;I; $"',.
                 ";;ii$SS;$; ..;.;"  ;$ ;$;; $'
                  "$$;::j;$.;;.;7   ;; ;; ; ;
                    "";::;i$:;;7   ;   ; ; '
                       "::i$i'    ;   ;  ;
                         ""'    ,'   ;  '
                                        '

.EXAMPLE
        SyscallPredator
        
        Direct-Syscall-Suspect
        Meta   event=StackWalk/Stack pid=24868 tid=50232 cpu=2 op=32 ver=2 ts=0x000006D2ED5E25C2
        Actor  callerImage=C:\.PREDATOR\DirectSyscallAgent.exe
               targetImage=\Device\HarddiskVolume3\.PREDATOR\DirectSyscallAgent.exe
        Origin addr=0x000000000040102A (DirectSyscallAgent.exe)
               path=\Device\HarddiskVolume3\.PREDATOR\DirectSyscallAgent.exe
        Stack  totalFrames=9
               #0 0x000000000040102A (DirectSyscallAgent.exe+0x102A)
               #1 0x0000000000401010 (DirectSyscallAgent.exe+0x1010)
               #2 0x00000000004010EA (DirectSyscallAgent.exe+0x10EA)
               #3 0x00007FF8AF9ECD87 (kernel32.dll+0x2CD87)
               #4 0x00007FF8B054CAEC (ntdll.dll+0xACAEC)
        Alert  Direct-Syscall classification observed.
#>
        [CmdletBinding(DefaultParameterSetName="ByName")]
        param(
                [Parameter(Mandatory=$false, ParameterSetName="ByName", Position=0)]
                [string] $TargetProcessName
        )

        #
        # Every newly loaded process will be tied to a hashmap:
        # Process hashmap -> ID : Thread hashmap
        #                       : Loaded modules list
        #
	$ProcessList			                        = @{}

        function GetModule {
                [CmdletBinding()]
                param(
                        [Parameter(Mandatory)]
                        [int] $ProcessID,

                        [Parameter(Mandatory)]
                        [UInt64] $Address
                )
                foreach ($Module in $ProcessList[$ProcessID].Modules) {
                        if (($Address -ge $Module.ImageBaseAddress) -and ($Address -le ($Module.ImageBaseAddress + $Module.ImageSize))) {
                                return $Module
                        }
                }
        }

	function GetCallStack {
                [CmdletBinding()]
                param(
                        [Parameter(Mandatory)]
                        [int] $ProcessID,

                        [Parameter(Mandatory)]
                        [UInt64] $Address
                )
                if (-not ($Module = GetModule $ProcessID $Address)) {
                        return "???"
                }
                return "{0}+0x{1:X}" -f $Module.ImageFileName, ($Address - $Module.ImageBaseAddress)
        }

	function ReportDirectSyscall {
                [CmdletBinding()]
                param(
                        [Parameter(Mandatory)]
                        [Microsoft.Diagnostics.Tracing.Parsers.Kernel.StackWalkStackTraceData] $Event
                )
                [Console]::Write((
                        "Direct-Syscall-Suspect `n"
                ))
                [Console]::Write((
                        "Meta   event={0} pid={1} tid={2} cpu={3} op={4} ver={5} ts=0x{6:X16}`n" -f
                        $Event.EventName,
                        $Event.ProcessID,
                        $Event.ThreadID,
                        $Event.ProcessorNumber,
                        $Event.Opcode,
                        $Event.Version,
                        $Event.EventTimeStampQPC
                ))
                for ($FrameIndex = 0; $FrameIndex -lt $Event.FrameCount; $FrameIndex++) {
                        if ([UInt64] $Event.InstructionPointer($FrameIndex) -le 0x7FFFFFFFFFFF) {
                                $FirstUserlandAddress = [UInt64] $Event.InstructionPointer($FrameIndex)
                                break
                        }
                }
                [Console]::Write((
                        "Actor  callerImage={0} `n       targetImage={1} `n" -f
                        ($ProcessList[$Event.ProcessID].Modules[0].ImageFilePath),
                        ($ProcessList[$Event.ProcessID].Modules[0].NTImageFilePath)
                ))
                [Console]::Write((
                        "Origin addr=0x{0:X16} ({1}) `n       path={2} `n" -f
                        $FirstUserlandAddress,
                        (GetModule $Event.ProcessID $FirstUserlandAddress).ImageFileName,
                        (GetModule $Event.ProcessID $FirstUserlandAddress).NTImageFilePath

                ))
                [Console]::Write((
                        "Stack  totalFrames={0} `n" -f
                        $Event.FrameCount
                ))
                for ($FrameIndex = 0; $FrameIndex -lt $Event.FrameCount; $FrameIndex++) {
                        if (($InstructionPointer = [UInt64] $Event.InstructionPointer($FrameIndex)) -gt 0x7FFFFFFFFFFF) {
                                $LastKernelFrameIndex = $FrameIndex
                                continue
                        }
                        [Console]::Write((
                                "       #{0} 0x{1:X16} ({2}) `n" -f 
                                ($FrameIndex - $LastKernelFrameIndex - 1),
                                $InstructionPointer,
                                (GetCallStack $Event.ProcessID $InstructionPointer)
                        ))
                }
                [Console]::Write("Alert  Direct-Syscall classification observed. `n`n")
        }

        $Assembly                                               = [Reflection.Assembly]::LoadFrom([IO.Path]::Combine($HOME, ".NUGET\PACKAGES\MICROSOFT.DIAGNOSTICS.TRACING.TRACEEVENT\3.2.6\LIB\NETSTANDARD2.0\MICROSOFT.DIAGNOSTICS.TRACING.TRACEEVENT.DLL"))
	$Session                                                = [Microsoft.Diagnostics.Tracing.Session.TraceEventSession]::new("EventTracing")
        $SessionKeywords                                        = [Microsoft.Diagnostics.Tracing.Parsers.KernelTraceEventParser+Keywords]
        $Result                                                 = $Session.EnableKernelProvider(
                $SessionKeywords::Process -bor
                $SessionKeywords::ImageLoad,
                $SessionKeywords::SystemCall
        )
        if (-not ($Assembly -and $Result)) {
                throw [PlatformNotSupportedException]::new("Please ensure PowerShell 7 or later & trace event assembly is installed.")
                return
        }
        $Source                                                 = $Session.Source
        $Kernel                                                 = $Source.Kernel

        #
        # If filtering is not applied, then the list hashmap exapnds.
        # Process hashmap -> ID : Thread hashmap
        #                       : Loaded modules list
        #
        $ProcessStartCallback                                   = [scriptblock] {
                [CmdletBinding()]
                param(
                        [Parameter(Mandatory)]
                        [Microsoft.Diagnostics.Tracing.Parsers.Kernel.ProcessTraceData] $Event
                )
                if ($TargetProcessName -and ($Event.ImageFileName -ne $TargetProcessName)) {
                        return
                }
                $ProcessList[$Event.ProcessID]                  = @{
                        Modules                                 = @()
                }
        }

        #
        # If reverse lookup succeeds, there is a value for loaded modules list.
        # Loaded modules list (Ordered in load order)
        #                -> Module hashmap -> NTImageFilePath  : Kernel image file path
        #                                     ImageFileName    : Native image file name
        #                                     ImageFilePath    : Native image file path
        #                                     ImageBaseAddress : Image start address
        #                                     ImageSize        : Image size
        #
        $ImageLoadCallback                                      = [scriptblock] {
                [CmdletBinding()]
                param(
                        [Parameter(Mandatory)]
                        [Microsoft.Diagnostics.Tracing.Parsers.Kernel.ImageLoadTraceData] $Event
                )
                if (-not $ProcessList.ContainsKey($Event.ProcessID)) {
                        return
                }
                $ProcessList[$Event.ProcessID].Modules         += @{
                        NTImageFilePath                         = $Event.GetType().GetProperty("KernelFileName", [System.Reflection.BindingFlags] "Instance, NonPublic" ).GetValue($Event)
                        ImageFileName                           = [IO.Path]::GetFileName($Event.FileName)
                        ImageFilePath                           = $Event.FileName
                        ImageBaseAddress                        = $Event.ImageBase
                        ImageSize                               = $Event.ImageSize
                }
        }

        #
        # All newly loaded or filtered processes will be tracked. A reverse lookup
        # will retrieve loaded modules by process by ID. Subsequent analysis will
        # determine benignity.
        #
        $StackWalkCallback                                      = [scriptblock] {
                [CmdletBinding()]
                param(
                        [Parameter(Mandatory)]
                        [Microsoft.Diagnostics.Tracing.Parsers.Kernel.StackWalkStackTraceData] $Event
                )
                if (-not $ProcessList.ContainsKey($Event.ProcessID)) {
                        return
                }
                for ($FrameIndex = 0; $FrameIndex -lt $Event.FrameCount; $FrameIndex++) {
                        if (($InstructionPointer = [UInt64] $Event.InstructionPointer($FrameIndex)) -gt 0x7FFFFFFFFFFF) {
                                continue
                        }
                        if ((GetModule $Event.ProcessID $InstructionPointer).ImageFilePath -eq ($ProcessList[$Event.ProcessID].Modules[0].ImageFilePath)) {
                                ReportDirectSyscall $Event
                        }
                        break
                }
        }

        $Kernel.add_ProcessStart($ProcessStartCallback)
        $Kernel.add_ImageLoad($ImageLoadCallback)
        $Kernel.add_StackWalkStack($StackWalkCallback)

        try { 
                $Result = $Source.PSObject.Methods["Process"].Invoke() 
        } finally {
                $Session.Dispose()
        }
}