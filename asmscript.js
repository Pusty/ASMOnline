//converting a byte array into a string
function dumpHex(encoding) {
    var output = ""
    for(i=0;i<encoding.length;i++) {
        let tmp = encoding[i].toString(16).toUpperCase();
        if(tmp.length != 2)
            tmp = "0"+tmp
        output += tmp+" ";
    }
    return output.trim()
}
//run a virual emulated enviorment with generic parameters
function run_generic(asmInput, START_ADDRESS, ks_arch, ks_mode, uc_arch, uc_mode, mode_name, default_inst, name_reg_array, reg_size) {
    asmOrg = asmInput
    if(asmInput.trim() == "")
        asmInput = default_inst //if no code is supplied put in a default
    asmInput = asmInput.replace(";", "\n") //; is equal to newline for keystone, this is important for proper line reporting
    try {
        output = ""
        ks_obj = new ks.Keystone(ks_arch, ks_mode) //configure Keystone with given generic parameters
        encoding = ks_obj.asm(asmInput) //run Keystone on the inputed assembly
        ks_obj.close() //delete opject
        outputBytes = dumpHex(encoding) //save hex representation of compiled assembly
        output += NL
        if(encoding == null || encoding.length == 0) {
            output += "Generic Keystone Assembling Error"
            return output //don't continue if no code was generated
        }
        CODE = encoding //change format of assembled code for unicorn
        mu = new uc.Unicorn(uc_arch, uc_mode) //configure Unicorn with given generic parameters
        mu.mem_map(START_ADDRESS, SIZE_OF_PAGE, uc.PROT_ALL) //reserve memory at given start address and size
        mu.mem_write(START_ADDRESS, CODE) //start writing the code to the page
        mu.emu_start(START_ADDRESS, START_ADDRESS + encoding.length,0,0)
        output += (">>> Dumping Registers ["+mode_name+"] <<<") //after that dump registers
        output += NL
        for(i=0;i<name_reg_array.length;i++) {
            let tmp = mu.reg_read_type(name_reg_array[i][1], reg_size)
            if(reg_size == 'i16') tmp = (tmp&0xFFFF) >>> 0                               //make unsigned
            if(reg_size == 'i32') tmp = (tmp&0xFFFFFFFF) >>> 0 
            if(reg_size == 'i64') tmp = tmp >>> 0 
            tmp = tmp.toString(16)

            while(reg_size == 'i16' && tmp.length < 4)
                tmp = "0"+tmp
            while(reg_size == 'i32' && tmp.length < 8)
                tmp = "0"+tmp
            while(reg_size == 'i64' && tmp.length < 8) //JS can't handle 64 bit numbers, and I personally don't really need 64bit number representation if internal calculation is still correct
                tmp = "0"+tmp
            output += (">>> "+name_reg_array[i][0]+" = 0x" + tmp)
            output += NL
        }
        mu.close()
    }catch(e) {
        output = e+"" //Report Generic Exception
        return output
    }
    return output
}
    
//Emulate x86 16 bit assembly (e.g. Real Mode/BIOS mode of a generic Intel processor)
function run_x86_16(asmInput) {
    return run_generic(asmInput, 0x0, ks.ARCH_X86,ks.MODE_16,uc.ARCH_X86,uc.MODE_16,"x86-16","nop",[["IP",uc.X86_REG_IP],["AX",uc.X86_REG_AX],["BX",uc.X86_REG_BX],["CX",uc.X86_REG_CX],["DX",uc.X86_REG_DX],["SI",uc.X86_REG_SI],["DI",uc.X86_REG_DI],["BP",uc.X86_REG_BP],["SP",uc.X86_REG_SP]], 'i16')
}
//Emulate x86 32 bit assembly (e.g. Protected Mode/normal execution of code on a generic Intel processor)
function run_x86_32(asmInput) {
    return run_generic(asmInput, 0x80000, ks.ARCH_X86,ks.MODE_32,uc.ARCH_X86,uc.MODE_32,"x86-32","nop",[["EIP",uc.X86_REG_EIP],["EAX",uc.X86_REG_EAX],["EBX",uc.X86_REG_EBX],["ECX",uc.X86_REG_ECX],["EDX",uc.X86_REG_EDX],["ESI",uc.X86_REG_ESI],["EDI",uc.X86_REG_EDI],["EBP",uc.X86_REG_EBP],["ESP",uc.X86_REG_ESP]], 'i32')
}
//Emulate x86 64 bit assembly (e.g. Long Mode/normal execution of code on a generic 64bit Intel processor)
function run_x86_64(asmInput) {
    return run_generic(asmInput, 0x80000, ks.ARCH_X86,ks.MODE_64,uc.ARCH_X86,uc.MODE_64,"x86-64","nop",[["RIP",uc.X86_REG_RIP],["RAX",uc.X86_REG_RAX],["RBX",uc.X86_REG_RBX],["RCX",uc.X86_REG_RCX],["RDX",uc.X86_REG_RDX],["RSI",uc.X86_REG_RSI],["RDI",uc.X86_REG_RDI],["RBP",uc.X86_REG_RBP],["R8&nbsp;",uc.X86_REG_R8],["R9&nbsp;",uc.X86_REG_R9],["R10",uc.X86_REG_R10],["R11",uc.X86_REG_R11],["R12",uc.X86_REG_R12],["R13",uc.X86_REG_R13],["R14",uc.X86_REG_R14],["R15",uc.X86_REG_R15],["RSP",uc.X86_REG_RSP]], 'i64')
}
//Emulate 32bit MIPS assembly (e.g. older Broadcom routers)
function run_MIPS32(asmInput) {
    ks_endian = ENDIANESS? ks.MODE_BIG_ENDIAN:ks.MODE_LITTLE_ENDIAN
    uc_endian = ENDIANESS? uc.MODE_BIG_ENDIAN:uc.MODE_LITTLE_ENDIAN
    return run_generic(asmInput, 0x10000, ks.ARCH_MIPS,ks.MODE_MIPS32+ks_endian,uc.ARCH_MIPS,uc.MODE_MIPS32+uc_endian,"MIPS32","nop",[["REG PC",uc.MIPS_REG_PC],["REG 0",uc.MIPS_REG_0],["REG 1",uc.MIPS_REG_1],["REG 2",uc.MIPS_REG_2],["REG 3",uc.MIPS_REG_3],["REG 4",uc.MIPS_REG_4],["REG 5",uc.MIPS_REG_5],["REG 6",uc.MIPS_REG_6],["REG 7",uc.MIPS_REG_7],["REG 8",uc.MIPS_REG_8],["REG 9",uc.MIPS_REG_9],["REG 10",uc.MIPS_REG_10],["REG 11",uc.MIPS_REG_11],["REG 12",uc.MIPS_REG_12],["REG 13",uc.MIPS_REG_13],["REG 14",uc.MIPS_REG_14],["REG 15",uc.MIPS_REG_15]],'i32')
}
//Emulate 64bit MIPS assembly (e.g. newer Broadcom routers)
function run_MIPS64(asmInput) {
    ks_endian = ENDIANESS? ks.MODE_BIG_ENDIAN:ks.MODE_LITTLE_ENDIAN
    uc_endian = ENDIANESS? uc.MODE_BIG_ENDIAN:uc.MODE_LITTLE_ENDIAN
    return run_generic(asmInput, 0x10000, ks.ARCH_MIPS,ks.MODE_MIPS64+ks_endian,uc.ARCH_MIPS,uc.MODE_MIPS64+uc_endian,"MIPS64","nop",[["REG PC",uc.MIPS_REG_PC],["REG 0",uc.MIPS_REG_0],["REG 1",uc.MIPS_REG_1],["REG 2",uc.MIPS_REG_2],["REG 3",uc.MIPS_REG_3],["REG 4",uc.MIPS_REG_4],["REG 5",uc.MIPS_REG_5],["REG 6",uc.MIPS_REG_6],["REG 7",uc.MIPS_REG_7],["REG 8",uc.MIPS_REG_8],["REG 9",uc.MIPS_REG_9],["REG 10",uc.MIPS_REG_10],["REG 11",uc.MIPS_REG_11],["REG 12",uc.MIPS_REG_12],["REG 13",uc.MIPS_REG_13],["REG 14",uc.MIPS_REG_14],["REG 15",uc.MIPS_REG_15]],'i64')
}
//Emulate ARM assembly in ARM mode (e.g. almost all Smartphones, Raspberry Pi)
function run_ARM(asmInput) {
    ks_endian = ENDIANESS? ks.MODE_BIG_ENDIAN:ks.MODE_LITTLE_ENDIAN
    uc_endian = ENDIANESS? uc.MODE_BIG_ENDIAN:uc.MODE_LITTLE_ENDIAN
    return run_generic(asmInput, 0x10000, ks.ARCH_ARM,ks.MODE_ARM+ks_endian,uc.ARCH_ARM,uc.MODE_ARM+uc_endian,"ARM","nop",[["PC",uc.ARM_REG_PC],["REG 0",uc.ARM_REG_R0],["REG 1",uc.ARM_REG_R1],["REG 2",uc.ARM_REG_R2],["REG 3",uc.ARM_REG_R3],["REG 4",uc.ARM_REG_R4],["REG 5",uc.ARM_REG_R5],["REG 6",uc.ARM_REG_R6],["REG 7",uc.ARM_REG_R7],["REG 8",uc.ARM_REG_R8],["REG 9",uc.ARM_REG_R9],["REG 10",uc.ARM_REG_R10],["REG 11",uc.ARM_REG_R11],["REG 12",uc.ARM_REG_R12],["REG 13",uc.ARM_REG_R13],["REG 14",uc.ARM_REG_R14],["REG 15",uc.ARM_REG_R15]],'i32')
}
//Emulate ARM assembly in Thumbs mode (e.g. almost all Smartphones, Raspberry Pi)
function run_THUMB(asmInput) {
    ks_endian = ENDIANESS? ks.MODE_BIG_ENDIAN:ks.MODE_LITTLE_ENDIAN
    uc_endian = ENDIANESS? uc.MODE_BIG_ENDIAN:uc.MODE_LITTLE_ENDIAN
    return run_generic(asmInput, 0x10000, ks.ARCH_ARM,ks.MODE_THUMB+ks_endian,uc.ARCH_ARM,uc.MODE_THUMB+uc_endian,"THUMB","nop",[["PC",uc.ARM_REG_PC],["R0",uc.ARM_REG_R0],["R1",uc.ARM_REG_R1],["R2",uc.ARM_REG_R2],["R3",uc.ARM_REG_R3],["R4",uc.ARM_REG_R4],["R5",uc.ARM_REG_R5],["R6",uc.ARM_REG_R6],["R7",uc.ARM_REG_R7],["R8",uc.ARM_REG_R8],["R9",uc.ARM_REG_R9],["R10",uc.ARM_REG_R10],["R11",uc.ARM_REG_R11],["R12",uc.ARM_REG_R12],["R13",uc.ARM_REG_R13],["R14",uc.ARM_REG_R14],["R15",uc.ARM_REG_R15]], 'i32')
}
//Emulate SPARC assembly (e.g. K computer, fasted Supercomputer 2011, 8th fasted Supercomputer 2018)
function run_SPARC(asmInput) {
    return run_generic(asmInput, 0x10000, ks.ARCH_SPARC,ks.MODE_SPARC32|ks.MODE_BIG_ENDIAN,uc.ARCH_SPARC,uc.MODE_SPARC32|uc.MODE_BIG_ENDIAN,"SPARC","nop",[["G0",uc.SPARC_REG_G0],["G1",uc.SPARC_REG_G1],["G2",uc.SPARC_REG_G2],["G3",uc.SPARC_REG_G3],["G4",uc.SPARC_REG_G4],["G5",uc.SPARC_REG_G5],["G6",uc.SPARC_REG_G6],["G7",uc.SPARC_REG_G7]], 'i32')
}


function defaultCommand(obj) {
    NL = "<br/>"
    SIZE_OF_PAGE = 2*1024*1024
    ENDIANESS = false //0 little, 1 big

    outputBytes = ""

    asmMode = document.getElementById("asm_mode").value
    asmInput = document.getElementById("asm_data").value
    outputStr = ""


    //decide which mode to run depending on option field
    if (asmMode == "ARCH_X86_32")
        outputStr += run_x86_32(asmInput)
    else if (asmMode == "ARCH_X86_16")
        outputStr += run_x86_16(asmInput)
    else if (asmMode == "ARCH_X86_64")
        outputStr += run_x86_64(asmInput)
    else if (asmMode == "ARCH_MIPS_MIPS32")
        outputStr += run_MIPS32(asmInput)
    else if (asmMode == "ARCH_MIPS_MIPS64")
        outputStr += run_MIPS64(asmInput)
    else if (asmMode == "ARCH_ARM_ARM")
        outputStr += run_ARM(asmInput)
    else if (asmMode == "ARCH_ARM_THUMB")
        outputStr += run_THUMB(asmInput)
    else if (asmMode == "ARCH_SPARC")
        outputStr += run_SPARC(asmInput)
    else
        outputStr += "Not implemented yet."
        
    //Update Website content for user
    document.getElementById("asm_data").innerHTML = asmInput
    document.getElementById("asm_bytecode").innerHTML = outputBytes
    document.getElementById("asm_output").innerHTML = outputStr
}
