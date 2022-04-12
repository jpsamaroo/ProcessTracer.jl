module ProcessTracer

using CEnum
using Printf

@cenum PTraceRequest begin
    PTRACE_TRACEME = 0
    PTRACE_PEEKTEXT = 1
    PTRACE_PEEKDATA = 2
    PTRACE_PEEKUSER = 3
    PTRACE_POKETEXT = 4
    PTRACE_POKEDATA = 5
    PTRACE_POKEUSER = 6
    PTRACE_CONT = 7
    PTRACE_KILL = 8
    PTRACE_SINGLESTEP = 9
    PTRACE_GETREGS = 12
    PTRACE_SETREGS = 13
    PTRACE_GETFPREGS = 14
    PTRACE_SETFPREGS = 15
    PTRACE_ATTACH = 16
    PTRACE_DETACH = 17
    PTRACE_GETFPXREGS = 18
    PTRACE_SETFPXREGS = 19
    PTRACE_SYSCALL = 24
    PTRACE_SETOPTIONS = 0x4200
    PTRACE_GETEVENTMSG = 0x4201
    PTRACE_GETSIGINFO = 0x4202
    PTRACE_SETSIGINFO = 0x4203
    PTRACE_GETREGSET = 0x4204
    PTRACE_SETREGSET = 0x4205
    PTRACE_SEIZE = 0x4206
    PTRACE_INTERRUPT = 0x4207
    PTRACE_LISTEN = 0x4208
    PTRACE_PEEKSIGINFO = 0x4209
    PTRACE_GETSIGMASK = 0x420a
    PTRACE_SETSIGMASK = 0x420b
    PTRACE_SECCOMP_GET_FILTER = 0x420c
    PTRACE_SECCOMP_GET_METADATA = 0x420d
    PTRACE_GET_SYSCALL_INFO = 0x420e
end
@cenum PTraceOption begin
    PTRACE_O_TRACESYSGOOD    = 0x00000001
    PTRACE_O_TRACEFORK       = 0x00000002
    PTRACE_O_TRACEVFORK      = 0x00000004
    PTRACE_O_TRACECLONE      = 0x00000008
    PTRACE_O_TRACEEXEC       = 0x00000010
    PTRACE_O_TRACEVFORKDONE  = 0x00000020
    PTRACE_O_TRACEEXIT       = 0x00000040
    PTRACE_O_TRACESECCOMP    = 0x00000080
    PTRACE_O_EXITKILL        = 0x00100000
    PTRACE_O_SUSPEND_SECCOMP = 0x00200000
    PTRACE_O_MASK            = 0x003000ff
end
@cenum WaitPidOption begin
    WNOHANG    = 1
    WUNTRACED  = 2
    WCONTINUED = 8
end

include("registers.jl")
include("syscalls.jl")

WEXITSTATUS(s) = (s & 0xff00) >> 8
WTERMSIG(s) = s & 0x7f
WSTOPSIG(s) = WEXITSTATUS(s)
WCOREDUMP(s) = s & 0x80
WIFEXITED(s) = WTERMSIG(s) == 0
WIFSTOPPED(s) = unsafe_trunc(Cshort, ((s & 0xffff) * 0x10001) >> 8) > 0x7f00
WIFSIGNALED(s) = (s & 0xffff)-1 < 0xff
WIFCONTINUED(s) = s == 0xffff

const SIGTRAP = 5

struct WaitStatus
    status::Cint
end
function Base.show(io::IO, ws::WaitStatus)
    s = ws.status
    print(io, "WaitStatus(")
    codes = String[]
    if WIFEXITED(s)
        exitcode = WEXITSTATUS(s)
        push!(codes, "Exited(Code $exitcode)")
    elseif WIFSIGNALED(s)
        sig = WTERMSIG(s)
        push!(codes, "Killed(Signal $sig)")
    elseif WIFSTOPPED(s)
        sig = WSTOPSIG(s)
        reason = if sig == SIGTRAP
            "At Breakpoint"
        elseif sig == SIGTRAP | 0x80
            "At Syscall"
        else
            "Unknown"
        end
        push!(codes, "Stopped($reason)")
    elseif WIFCONTINUED(s)
        push!(codes, "Running")
    end
    print(io, join(codes, ", "))
    print(io, ")")
end

function ptrace(request::PTraceRequest, pid::Cint, addr::Ptr{Cvoid}=C_NULL, data=C_NULL)
    if data isa Int32
        data = Ptr{Cvoid}(Int(data))
    end
    ret = ccall(:ptrace, Clong, (Cint, Cint, Ptr{Cvoid}, Ptr{Cvoid}),
                request, pid, addr, data)
    @assert ret == 0 "ptrace($request): $ret"
end
function personality(persona::Culong)
    ret = ccall(:personality, Cint, (Culong,), persona)
    @assert ret == 0 "personality: $ret"
end
function waitpid(pid::Cint, options=Cint(0))
    wstatus = Ref{Cint}(0)
    ret = ccall(:waitpid, Cint, (Cint, Ptr{Cint}, Cint),
                pid, wstatus, options)
    @assert ret == pid "waitpid($pid): $ret"
    return WaitStatus(wstatus[])
end

mutable struct Tracee
    pid::Cint
    status::WaitStatus
    in_syscall::Bool
    in_execve::Bool
end
Tracee(pid) = Tracee(pid, WaitStatus(0xffff), true, false)
function Base.show(io::IO, t::Tracee)
    print(io, "Tracee(")
    show(io, t.status)
    syscall = get_syscall(t)
    print(io, ", $(t.in_syscall ? "Syscall Entry" : "Syscall Exit"), $syscall)")
end

function trace_pid(pid::Cint)
    # Attach to process
    ptrace(PTRACE_ATTACH, pid)
    # Wait on process to exec
    status = waitpid(pid, 0)
    # Trace syscalls, kill on exit
    ptrace(PTRACE_SETOPTIONS, pid, C_NULL, PTRACE_O_TRACESYSGOOD|PTRACE_O_EXITKILL)
end
function trace_cmd(cmd::Base.AbstractCmd)
    cmd = deepcopy(cmd)
    exec = cmd isa Base.CmdRedirect ? cmd.cmd.exec : cmd.exec
    pushfirst!(exec, joinpath(@__DIR__, "tracee"))
    p = run(cmd; wait=false)
    pid = getpid(p)
    trace_pid(pid)
    return Tracee(pid)
end

function run_to_syscall(pid)
    ptrace(PTRACE_SYSCALL, Cint(pid))
    return waitpid(Cint(pid), 0)
end
function run_to_syscall(t::Tracee)
    if WIFEXITED(t.status.status) || WIFSIGNALED(t.status.status)
        error("Tracee exited")
    end
    t.status = run_to_syscall(t.pid)
    syscall = get_syscall(t)
    # N.B. If we enter an execve(), we will either:
    # - Return from it normally (execve() failed)
    # - Never exit it
    if !t.in_execve || syscall == SYS_execve
        t.in_syscall = !t.in_syscall
        t.in_execve = t.in_syscall && syscall == SYS_execve
    else
        @assert t.in_execve
        t.in_syscall = true
        t.in_execve = false
    end
    t
end

function get_registers(pid)
    regs = Ref{UserRegs}()
    regs_ptr = Ptr{Cvoid}(Base.unsafe_convert(Ptr{UserRegs}, regs))
    ptrace(PTRACE_GETREGS, pid, C_NULL, regs_ptr)
    regs[]
end
get_registers(t::Tracee) = get_registers(t.pid)
function set_registers!(pid, regs::UserRegs)
    regs = Reg{UserRegs}(regs)
    regs_ptr = Ptr{Cvoid}(Base.unsafe_convert(Ptr{UserRegs}, regs))
    ptrace(PTRACE_SETREGS, pid, C_NULL, regs_ptr)
end
set_registers!(t::Tracee, regs::UserRegs) = set_registers!(t.pid, regs)
get_syscall(pid) = Syscall(get_registers(pid).orig_rax)
get_syscall(t::Tracee) = get_syscall(t.pid)

#= TODO: Would be nice if this could work
function traceme()
    ptrace(PTRACE_TRACEME, 0, C_NULL, C_NULL)
    personality(ADDR_NORANDOMIZE)
end
function fork_exec_inner(cmd, args)
    pid = ccall(:fork, Cint, ())
    if pid == -1
        Base.systemerror(pid)
    elseif pid == 0
        # Child
        #ccall(:close, Cint, (Cint,), 0)
        #ccall(:close, Cint, (Cint,), 1)
        #ccall(:close, Cint, (Cint,), 2)
        #f(pid)
        ret = ccall(:execv, Cvoid, (Ptr{Cuchar}, Ptr{Ptr{Cuchar}}),
                    cmd, args)
        Base.systemerror(ret)
    end
    return nothing
end
function fork_exec(f, cmd::Cmd)
    GC.@preserve cmd begin
        args = map(pointer, cmd.exec)
        push!(args, Ptr{Cuchar}(0))
        cmd = first(args)
        fork_exec_inner_ptr = @cfunction(fork_exec_inner, Cvoid, (Ptr{Cuchar}, Ptr{Ptr{Cuchar}}))
        ccall(fork_exec_inner_ptr, Cvoid, (Ptr{Cuchar}, Ptr{Ptr{Cuchar}}), cmd, args)
    end
end
=#

end # module
