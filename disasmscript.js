function mnemonic(event) {
    //check if the content of the mnemonics textbox was changed
	var data = hash(document.getElementById("disasm_mnemonic").value);
	if(data != document.getElementById("mnemonic_hash").innerHTML) {
        run(true)
		document.getElementById("mnemonic_hash").innerHTML = data;
        document.getElementById("hex_hash").innerHTML = hash(document.getElementById("disasm_hex").value);
	}
}

function hex(event) {
    //check if the content of the hex textbox was changed
	var data = hash(document.getElementById("disasm_hex").value);
	if(data != document.getElementById("hex_hash").innerHTML) {
        run(false)
		document.getElementById("hex_hash").innerHTML = data;
        document.getElementById("mnemonic_hash").innerHTML = hash(document.getElementById("disasm_mnemonic").value);
	}
}

function hash(str) {
    var hash = 0;
    if (str.length == 0)
        return hash;
    for (var i = 0; i < str.length; i++) {
        var char = str.charCodeAt(i);
        hash = ((hash<<5)-hash)+char;
        hash = hash & hash;
    }
    return hash;
}

NL = "\n"

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

//parse hex string from hex textbox to bytearray
function parseHex(hexstring) {
    try {
        l = []
        hexstring = hexstring.trim()
        hexstring = hexstring.replace("0x"," ").replace("h"," ").replace(","," ").replace("["," ").replace("]"," ").replace("("," ").replace(")"," ").replace(";"," ")
        if(hexstring.indexOf(" ") == -1 && hexstring.length%2==0) {
            for(let i=0;i<hexstring.length/2;i++)
                l.push(parseInt(hexstring[i*2]+hexstring[i*2+1],16))
        }else {
            let cl = hexstring.split(" ")
            for(let i=0;i<cl.length;i++)
                if(cl[i].trim()!="")
                    l.push(parseInt(cl[i].trim(), 16))
        }
        return l
    }catch(e) {
        return []
    }
}

//assemble or disassemble with generic parameters
function run_generic(mnemonics_in,hexs_in,cs_arch,cs_mode,ks_arch,ks_mode,direction) {
    mnemonics_out = ""
    hexs_out      = ""
    if(direction) { //assemble
        try {
            mnemonics_out = mnemonics_in //mnemonic textbox content won't change as we assemble to hex
            ks_obj = new ks.Keystone(ks_arch, ks_mode) //configure Keystone
            encoding = ks_obj.asm(mnemonics_in) //assemble code
            ks_obj.close()
            hexs_out = dumpHex(encoding) //and output it in hex format
        }catch(e) { hexs_out = ""; }
    }else {
        try {
            hexs_out = hexs_in //hex textbox content won't change as we disassemble hex to assembly
            cs_obj = new cs.Capstone(cs_arch, cs_mode)
            encoding = parseHex(hexs_in)
            CODE = encoding
            mnemonics_out = ""
            disasm = cs_obj.disasm(CODE, 0x0)
            cs_obj.close()
            for(let i=0;i<disasm.length;i++) {
                mnemonics_out += (disasm[i].mnemonic+" "+disasm[i].op_str).trim() //format instructions and additional data
                mnemonics_out += NL
            }
        }catch(e) { mnemonics_out = ""; }
    }
    return [mnemonics_out, hexs_out]
}
function defaultCommand(obj) {
    run(true);
}
function run(editValue) {

    disasmMode = document.getElementById("disasm_mode").value
    mnemonics = document.getElementById("disasm_mnemonic").value
    hexs = document.getElementById("disasm_hex").value
    mnemonics_out = ""
    hexs_out = ""
    editField = editValue

    //choose mode depending on selected option
    if (disasmMode == "ARCH_X86_32")
        data = run_generic(mnemonics,hexs,cs.ARCH_X86,cs.MODE_32,ks.ARCH_X86,ks.MODE_32,editField)
    else if (disasmMode == "ARCH_X86_16")
        data = run_generic(mnemonics,hexs,cs.ARCH_X86,cs.MODE_16,ks.ARCH_X86,ks.MODE_16,editField)
    else if (disasmMode == "ARCH_X86_64")
        data = run_generic(mnemonics,hexs,cs.ARCH_X86,cs.MODE_64,ks.ARCH_X86,ks.MODE_64,editField)
    else if (disasmMode == "ARCH_MIPS_MIPS32")
        data = run_generic(mnemonics,hexs,cs.ARCH_MIPS,cs.MODE_MIPS32,ks.ARCH_MIPS,ks.MODE_MIPS32,editField)
    else if (disasmMode == "ARCH_MIPS_MIPS64")
        data = run_generic(mnemonics,hexs,cs.ARCH_MIPS,cs.MODE_MIPS64,ks.ARCH_MIPS,ks.MODE_MIPS64,editField)
    else if (disasmMode == "ARCH_ARM_ARM")
        data = run_generic(mnemonics,hexs,cs.ARCH_ARM,cs.MODE_ARM,ks.ARCH_ARM,ks.MODE_ARM,editField)
    else if (disasmMode == "ARCH_ARM_THUMB")
        data = run_generic(mnemonics,hexs,cs.ARCH_ARM,cs.MODE_THUMB,ks.ARCH_ARM,ks.MODE_THUMB,editField)
    else if (disasmMode == "ARCH_MIPS_MIPS32_BE")
        data = run_generic(mnemonics,hexs,cs.ARCH_MIPS,cs.MODE_MIPS32|cs.MODE_BIG_ENDIAN,ks.ARCH_MIPS,ks.MODE_MIPS32|ks.MODE_BIG_ENDIAN,editField)
    else if (disasmMode == "ARCH_MIPS_MIPS64_BE")
        data = run_generic(mnemonics,hexs,cs.ARCH_MIPS,cs.MODE_MIPS64|cs.MODE_BIG_ENDIAN,ks.ARCH_MIPS,ks.MODE_MIPS64|ks.MODE_BIG_ENDIAN,editField)
    else if (disasmMode == "ARCH_ARM_ARM_BE")
        data = run_generic(mnemonics,hexs,cs.ARCH_ARM,cs.MODE_ARM|cs.MODE_BIG_ENDIAN,ks.ARCH_ARM,ks.MODE_ARM|ks.MODE_BIG_ENDIAN,editField)
    else if (disasmMode == "ARCH_ARM_THUMB_BE")
        data = run_generic(mnemonics,hexs,cs.ARCH_ARM,cs.MODE_THUMB|cs.MODE_BIG_ENDIAN,ks.ARCH_ARM,ks.MODE_THUMB|ks.MODE_BIG_ENDIAN,editField)
    else if (disasmMode == "ARCH_SPARC")
        data = run_generic(mnemonics,hexs,cs.ARCH_SPARC,cs.MODE_BIG_ENDIAN,ks.ARCH_SPARC,ks.MODE_SPARC32|ks.MODE_BIG_ENDIAN,editField)

    document.getElementById("disasm_hex").value = data[1]
    document.getElementById("disasm_mnemonic").value = data[0]
}
