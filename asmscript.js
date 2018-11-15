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

function checkLines(asmInput, ks_obj) {
    highlights = []
	asmSplit = asmInput.split("\n").forEach(function(s) {
		try { ks_obj.asm(s); }catch(e) {
			//console.log("Error @ "+s);
            highlights.push({highlight:s,className:"red"});
		}
	});
    $('#asm_data').highlightWithinTextarea({highlight:highlights});
}

function localStorageSave() {
    localStorage.setItem('asm_data', $("#asm_data")[0].innerHTML);
    localStorage.setItem('asm_mode', $("#asm_mode")[0].value);
}

function localStorageLoad() {
    if(localStorage.getItem('asm_data') != null)
        $("#asm_data")[0].innerHTML = localStorage.getItem('asm_data');
    if(localStorage.getItem('asm_mode') != null)
        $("#asm_mode")[0].value     = localStorage.getItem('asm_mode');
}

isRunning = false;
singleStepUC = null;
singleStepLength = 0;
singleStepFunction = function(mu) {}
singleStepState = 0;
singleStepHook = null;

debuggingConfig = {}

function changeRegisterSetting(target) {
    obj = debuggingConfig[$("#asm_mode")[0].value];
    if(obj == null)
        obj = {};
    var selectedValue = target.options[target.selectedIndex].value;
    if(selectedValue == "Remove") {
        obj[target.id] = {state:"hidden"}
    }
    debuggingConfig[$("#asm_mode")[0].value] = obj;
}

//run a virual emulated enviorment with generic parameters
function run_generic(asmInput, START_ADDRESS, ks_arch, ks_mode, uc_arch, uc_mode, mode_name, default_inst, name_reg_array, reg_size, singleStep) {
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
        ip = 0;
        if(!singleStep || singleStepUC == null) {
            mu = new uc.Unicorn(uc_arch, uc_mode) //configure Unicorn with given generic parameters
            localStorageSave();
            if(singleStep) {
                singleStepUC = mu;
                ip = START_ADDRESS;
                //I would love to step instruction wise, but the moment I try to HOOK_CODE ax/eax/rax gets replaced with eflags?!
                singleStepHook = singleStepUC.hook_add(uc.HOOK_BLOCK, function(handle, address, addr_hi, size, user_data) {
                     $('#asm_bytecode').highlightWithinTextarea({highlight:[(address-START_ADDRESS)*3,(address-START_ADDRESS+size)*3],className:"bp"});
                     singleStepLength = size;
                 if(singleStepState%2 == 0)  {
                    singleStepUC.emu_stop();
                 }
                    singleStepState+=1;
            });
            }
            mu.mem_map(START_ADDRESS, SIZE_OF_PAGE, uc.PROT_ALL) //reserve memory at given start address and size
            singleStepState = 0;
            mu.mem_write(START_ADDRESS, CODE) //start writing the code to the page
            {
                STACK = START_ADDRESS+SIZE_OF_PAGE*2;
                mu.mem_map(STACK, SIZE_OF_PAGE, uc.PROT_ALL); //create a stack thingy
                last = name_reg_array[name_reg_array.length-1];
                mu.reg_write_type(last[1], reg_size, STACK+SIZE_OF_PAGE/2);
                
            }
            
            mu.hook_add(uc.HOOK_MEM_READ_UNMAPPED | uc.HOOK_MEM_WRITE_UNMAPPED, function(mu, access,address, user_data, size, arg) {
                 address = mu.reg_read_type(name_reg_array[0][1], reg_size);
                 size = 1;
                 $('#asm_bytecode').highlightWithinTextarea({highlight:[(address-START_ADDRESS)*3,(address-START_ADDRESS+size)*3],className:"bp"});
            });
            isRunning = true;
        }
        if(!singleStep)
            mu.emu_start(START_ADDRESS, START_ADDRESS + encoding.length)
        else {
            if(ip == 0)
                ip = singleStepUC.reg_read_type(name_reg_array[0][1], reg_size)
            singleStepUC.emu_start(ip, START_ADDRESS + encoding.length);
            if(mu.reg_read_type(name_reg_array[0][1], reg_size) >= START_ADDRESS + encoding.length)
                singleStepUC = null;
        }
        if(singleStep) {
            singleStepFunction(mu);
            //console.log(mu.reg_read_type(name_reg_array[0][1], reg_size).toString(16));
        }
        output = updateValues(mu,mode_name,name_reg_array,reg_size);
        if(!singleStep)  {
            isRunning = false;
            singleStepUC = null;
            mu.close()
        }
        isRunning = true;
    }catch(e) {
        console.log(e)
        output = e+"" //Report Generic Exception
        ks_obj = new ks.Keystone(ks_arch, ks_mode)
        checkLines(asmInput, ks_obj)
        ks_obj.close() 
        isRunning = false;
        singleStepUC = null;
        return output
    }
    return output
}

function updateValues(ucObj,mode_name,name_reg_array,reg_size) {
        output += (">>> Dumping Registers ["+mode_name+"] <<<") //after that dump registers
        output += NL
        output += ("<table>")
        for(i=0;i<name_reg_array.length;i++) {
            if(debuggingConfig[$("#asm_mode")[0].value] != null
            && debuggingConfig[$("#asm_mode")[0].value]["register_"+i] != null
            && debuggingConfig[$("#asm_mode")[0].value]["register_"+i]["state"]  != null
            && debuggingConfig[$("#asm_mode")[0].value]["register_"+i]["state"] == "hidden") continue;
            let tmp = ucObj.reg_read_type(name_reg_array[i][1], reg_size)
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
            output += ("<tr>")
            output += ("<td>")
            output += (">>> ")
            output += ("</td>")
            output += ("<td>")
            output += "<select id='register_"+i+"' onchange='changeRegisterSetting(event.target || event.srcElement)'>"
            output += ("<option disabled='disabled' selected='selected'>"+name_reg_array[i][0]+"</option>")
            //output += ("<option>Remove</option>")
            output += "</select>"
            output += ("</td>")
            output += ("<td>")
            output += " = 0x" + tmp
            output += ("</td>")
            output += ("</tr>")
        }
        output += ("</table>")
        document.getElementById("asm_output").innerHTML = output
        return output;
}

X86_16_REGISTERS = [["IP",uc.X86_REG_IP],["AX",uc.X86_REG_AX],["BX",uc.X86_REG_BX],["CX",uc.X86_REG_CX],["DX",uc.X86_REG_DX],["SI",uc.X86_REG_SI],["DI",uc.X86_REG_DI],["BP",uc.X86_REG_BP],["SP",uc.X86_REG_SP]]
X86_32_REGISTERS = [["EIP",uc.X86_REG_EIP],["EAX",uc.X86_REG_EAX],["EBX",uc.X86_REG_EBX],["ECX",uc.X86_REG_ECX],["EDX",uc.X86_REG_EDX],["ESI",uc.X86_REG_ESI],["EDI",uc.X86_REG_EDI],["EBP",uc.X86_REG_EBP],["ESP",uc.X86_REG_ESP]]
X86_64_REGISTERS = [["RIP",uc.X86_REG_RIP],["RAX",uc.X86_REG_RAX],["RBX",uc.X86_REG_RBX],["RCX",uc.X86_REG_RCX],["RDX",uc.X86_REG_RDX],["RSI",uc.X86_REG_RSI],["RDI",uc.X86_REG_RDI],["RBP",uc.X86_REG_RBP],["R8&nbsp;",uc.X86_REG_R8],["R9&nbsp;",uc.X86_REG_R9],["R10",uc.X86_REG_R10],["R11",uc.X86_REG_R11],["R12",uc.X86_REG_R12],["R13",uc.X86_REG_R13],["R14",uc.X86_REG_R14],["R15",uc.X86_REG_R15],["RSP",uc.X86_REG_RSP]]
MIPS32_REGISTERS = [["REG PC",uc.MIPS_REG_PC],["REG 0",uc.MIPS_REG_0],["REG 1",uc.MIPS_REG_1],["REG 2",uc.MIPS_REG_2],["REG 3",uc.MIPS_REG_3],["REG 4",uc.MIPS_REG_4],["REG 5",uc.MIPS_REG_5],["REG 6",uc.MIPS_REG_6],["REG 7",uc.MIPS_REG_7],["REG 8",uc.MIPS_REG_8],["REG 9",uc.MIPS_REG_9],["REG 10",uc.MIPS_REG_10],["REG 11",uc.MIPS_REG_11],["REG 12",uc.MIPS_REG_12],["REG 13",uc.MIPS_REG_13],["REG 14",uc.MIPS_REG_14],["REG 15",uc.MIPS_REG_15]]
MIPS64_REGISTERS = [["REG PC",uc.MIPS_REG_PC],["REG 0",uc.MIPS_REG_0],["REG 1",uc.MIPS_REG_1],["REG 2",uc.MIPS_REG_2],["REG 3",uc.MIPS_REG_3],["REG 4",uc.MIPS_REG_4],["REG 5",uc.MIPS_REG_5],["REG 6",uc.MIPS_REG_6],["REG 7",uc.MIPS_REG_7],["REG 8",uc.MIPS_REG_8],["REG 9",uc.MIPS_REG_9],["REG 10",uc.MIPS_REG_10],["REG 11",uc.MIPS_REG_11],["REG 12",uc.MIPS_REG_12],["REG 13",uc.MIPS_REG_13],["REG 14",uc.MIPS_REG_14],["REG 15",uc.MIPS_REG_15]]
ARM_REGISTERS    = [["PC",uc.ARM_REG_PC],["REG 0",uc.ARM_REG_R0],["REG 1",uc.ARM_REG_R1],["REG 2",uc.ARM_REG_R2],["REG 3",uc.ARM_REG_R3],["REG 4",uc.ARM_REG_R4],["REG 5",uc.ARM_REG_R5],["REG 6",uc.ARM_REG_R6],["REG 7",uc.ARM_REG_R7],["REG 8",uc.ARM_REG_R8],["REG 9",uc.ARM_REG_R9],["REG 10",uc.ARM_REG_R10],["REG 11",uc.ARM_REG_R11],["REG 12",uc.ARM_REG_R12],["REG 13",uc.ARM_REG_R13],["REG 14",uc.ARM_REG_R14],["REG 15",uc.ARM_REG_R15]]
THUMB_REGISTERS  = [["PC",uc.ARM_REG_PC],["R0",uc.ARM_REG_R0],["R1",uc.ARM_REG_R1],["R2",uc.ARM_REG_R2],["R3",uc.ARM_REG_R3],["R4",uc.ARM_REG_R4],["R5",uc.ARM_REG_R5],["R6",uc.ARM_REG_R6],["R7",uc.ARM_REG_R7],["R8",uc.ARM_REG_R8],["R9",uc.ARM_REG_R9],["R10",uc.ARM_REG_R10],["R11",uc.ARM_REG_R11],["R12",uc.ARM_REG_R12],["R13",uc.ARM_REG_R13],["R14",uc.ARM_REG_R14],["R15",uc.ARM_REG_R15]]
SPARC_REGISTERS  = [["G0",uc.SPARC_REG_G0],["G1",uc.SPARC_REG_G1],["G2",uc.SPARC_REG_G2],["G3",uc.SPARC_REG_G3],["G4",uc.SPARC_REG_G4],["G5",uc.SPARC_REG_G5],["G6",uc.SPARC_REG_G6],["G7",uc.SPARC_REG_G7]]

//Emulate x86 16 bit assembly (e.g. Real Mode/BIOS mode of a generic Intel processor)
function run_x86_16(asmInput, singleStep) {
    return run_generic(asmInput, 0x0, ks.ARCH_X86,ks.MODE_16,uc.ARCH_X86,uc.MODE_16,"x86-16","nop",X86_16_REGISTERS, 'i16', singleStep)
}
//Emulate x86 32 bit assembly (e.g. Protected Mode/normal execution of code on a generic Intel processor)
function run_x86_32(asmInput, singleStep) {
    return run_generic(asmInput, 0x80000, ks.ARCH_X86,ks.MODE_32,uc.ARCH_X86,uc.MODE_32,"x86-32","nop",X86_32_REGISTERS, 'i32', singleStep)
}
//Emulate x86 64 bit assembly (e.g. Long Mode/normal execution of code on a generic 64bit Intel processor)
function run_x86_64(asmInput, singleStep) {
    return run_generic(asmInput, 0x80000, ks.ARCH_X86,ks.MODE_64,uc.ARCH_X86,uc.MODE_64,"x86-64","nop",X86_64_REGISTERS, 'i64', singleStep)
}
//Emulate 32bit MIPS assembly (e.g. older Broadcom routers)
function run_MIPS32(asmInput, singleStep) {
    ks_endian = ENDIANESS? ks.MODE_BIG_ENDIAN:ks.MODE_LITTLE_ENDIAN
    uc_endian = ENDIANESS? uc.MODE_BIG_ENDIAN:uc.MODE_LITTLE_ENDIAN
    return run_generic(asmInput, 0x10000, ks.ARCH_MIPS,ks.MODE_MIPS32+ks_endian,uc.ARCH_MIPS,uc.MODE_MIPS32+uc_endian,"MIPS32","nop",MIPS32_REGISTERS,'i32', singleStep)
}
//Emulate 64bit MIPS assembly (e.g. newer Broadcom routers)
function run_MIPS64(asmInput, singleStep) {
    ks_endian = ENDIANESS? ks.MODE_BIG_ENDIAN:ks.MODE_LITTLE_ENDIAN
    uc_endian = ENDIANESS? uc.MODE_BIG_ENDIAN:uc.MODE_LITTLE_ENDIAN
    return run_generic(asmInput, 0x10000, ks.ARCH_MIPS,ks.MODE_MIPS64+ks_endian,uc.ARCH_MIPS,uc.MODE_MIPS64+uc_endian,"MIPS64","nop",MIPS64_REGISTERS,'i64', singleStep)
}
//Emulate ARM assembly in ARM mode (e.g. almost all Smartphones, Raspberry Pi)
function run_ARM(asmInput, singleStep) {
    ks_endian = ENDIANESS? ks.MODE_BIG_ENDIAN:ks.MODE_LITTLE_ENDIAN
    uc_endian = ENDIANESS? uc.MODE_BIG_ENDIAN:uc.MODE_LITTLE_ENDIAN
    return run_generic(asmInput, 0x10000, ks.ARCH_ARM,ks.MODE_ARM+ks_endian,uc.ARCH_ARM,uc.MODE_ARM+uc_endian,"ARM","nop",ARM_REGISTERS,'i32', singleStep)
}
//Emulate ARM assembly in Thumbs mode (e.g. almost all Smartphones, Raspberry Pi)
function run_THUMB(asmInput, singleStep) {
    ks_endian = ENDIANESS? ks.MODE_BIG_ENDIAN:ks.MODE_LITTLE_ENDIAN
    uc_endian = ENDIANESS? uc.MODE_BIG_ENDIAN:uc.MODE_LITTLE_ENDIAN
    return run_generic(asmInput, 0x10000, ks.ARCH_ARM,ks.MODE_THUMB+ks_endian,uc.ARCH_ARM,uc.MODE_THUMB+uc_endian,"THUMB","nop",THUMB_REGISTERS, 'i32', singleStep)
}
//Emulate SPARC assembly (e.g. K computer, fasted Supercomputer 2011, 8th fasted Supercomputer 2018)
function run_SPARC(asmInput, singleStep) {
    return run_generic(asmInput, 0x10000, ks.ARCH_SPARC,ks.MODE_SPARC32|ks.MODE_BIG_ENDIAN,uc.ARCH_SPARC,uc.MODE_SPARC32|uc.MODE_BIG_ENDIAN,"SPARC","nop",SPARC_REGISTERS, 'i32', singleStep)
}

function initRun(obj, singleStep) {
    NL = "<br/>"
    SIZE_OF_PAGE = 4*1024
    ENDIANESS = false //0 little, 1 big

    outputBytes = ""    
    asmMode = document.getElementById("asm_mode").value
    asmInput = document.getElementById("asm_data").value
    outputStr = ""
    //decide which mode to run depending on option field
    if (asmMode == "ARCH_X86_32")
        outputStr += run_x86_32(asmInput, singleStep)
    else if (asmMode == "ARCH_X86_16")
        outputStr += run_x86_16(asmInput, singleStep)
    else if (asmMode == "ARCH_X86_64")
        outputStr += run_x86_64(asmInput, singleStep)
    else if (asmMode == "ARCH_MIPS_MIPS32")
        outputStr += run_MIPS32(asmInput, singleStep)
    else if (asmMode == "ARCH_MIPS_MIPS64")
        outputStr += run_MIPS64(asmInput, singleStep)
    else if (asmMode == "ARCH_ARM_ARM")
        outputStr += run_ARM(asmInput, singleStep)
    else if (asmMode == "ARCH_ARM_THUMB")
        outputStr += run_THUMB(asmInput, singleStep)
    else if (asmMode == "ARCH_SPARC")
        outputStr += run_SPARC(asmInput, singleStep)
    else
        outputStr += "Not implemented yet."

    //Update Site content for user
    document.getElementById("asm_data").innerHTML = asmInput
    document.getElementById("asm_bytecode").innerHTML = outputBytes
    document.getElementById("asm_output").innerHTML = outputStr
}
function resetSingle() {
    if(singleStepUC != null || isRunning) {
        isRunning = false;
        singleStepUC = null;
        $('#asm_data').highlightWithinTextarea({highlight:""});
        $('#asm_bytecode').highlightWithinTextarea({highlight:""});
    }
    return true;
}
function defaultCommand(obj) {
    initRun(obj, false);
    resetSingle();
}

function singleStep(obj) {
    initRun(obj, true);
}
