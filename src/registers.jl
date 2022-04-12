@cenum Register begin
    REG_rax
    REG_rbx
    REG_rcx
    REG_rdx
    REG_rdi
    REG_rsi
    REG_rbp
    REG_rsp
    REG_r8
    REG_r9
    REG_r10
    REG_r11
    REG_r12
    REG_r13
    REG_r14
    REG_r15
    REG_rip
    REG_rflags
    REG_cs
    REG_orig_rax
    REG_fs_base
    REG_gs_base
    REG_fs
    REG_gs
    REG_ss
    REG_ds
    REG_es
end
struct UserRegs
    r15::Culong
    r14::Culong
    r13::Culong
    r12::Culong
    rbp::Culong
    rbx::Culong
    r11::Culong
    r10::Culong
    r9::Culong
    r8::Culong
    rax::Culong
    rcx::Culong
    rdx::Culong
    rsi::Culong
    rdi::Culong
    orig_rax::Culong
    rip::Culong
    cs::Culong
    eflags::Culong
    rsp::Culong
    ss::Culong
    fs_base::Culong
    gs_base::Culong
    ds::Culong
    es::Culong
    fs::Culong
    gs::Culong
end
function Base.show(io::IO, regs::UserRegs)
    println(io, "UserRegs:")
    for field in fieldnames(UserRegs)
        reg = getfield(regs, field)
        str = @sprintf "%8s: 0x%.16x" field reg
        println(io, str)
    end
end
