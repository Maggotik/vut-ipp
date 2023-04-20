#-------------------
# autor: Jakub Vano
# login: xvanoj00
# datum: 11.4.2022
#-------------------
import re
import sys
import argparse
import xml.etree.ElementTree as ET

frames={"GF": {}}
framestack=[] 
datastack=[]
order=[]
labels=[]
calls=[]
instructions = []
inputfile=sys.stdin
sourcefile=sys.stdin
count = 0

parser = argparse.ArgumentParser(add_help=False)    
parser.add_argument("--help", action="store_true")
parser.add_argument("--source", dest="source")
parser.add_argument("--input", dest="input")

# Pomocne funkcie pre interpretaciu
def framecheck(arg):
    if arg not in frames:
        sys.exit(55)

def getvar(arg):
    return arg["value"][0:2], arg["value"][3:]


def getval(arg):
    if arg["type"] == "var":
        frame, name = getvar(arg)
        varcheck(frame, name)
        if frames[frame][name]["value"] == None:
            sys.exit(56)
        if frames[frame][name]["type"] == "int":
            return int(frames[frame][name]["value"])
        return frames[frame][name]["value"]
    else:
        if arg["type"] == "int":
            return int(arg["value"])
        return arg["value"]
        
def gettype(arg):
    if arg["type"] == "var":
        frame, name = getvar(arg)
        varcheck(frame, name)
        if frames[frame][name]["type"] == None:
            sys.exit(56)
        return frames[frame][name]["type"]
    else:
        return arg["type"]

def varcheck(frame, name):
    if frame not in frames:
        sys.exit(55)
    if name not in frames[frame]:
        sys.exit(54)
        
def isint(type):
    if type != "int":
        sys.exit(53)

def findlabels(code):
    cnt = 0
    while cnt < len(code):
        if code[cnt]["instruction"] == "LABEL":
            for l in labels:
                if code[cnt]["args"][0]["value"] in l["label"]:
                    sys.exit(52)
            labels.append({"label": code[cnt]["args"][0]["value"], "order": cnt})
        cnt += 1
#-----------------------------------------------------------------------------------------------------------------

# Funkcie pre jednotlive instrukcie jazyka IPPcode22
def move(args):
    frame, name = getvar(args[0])
    framecheck(frame)
    varcheck(frame, name)
    frames[frame][name] = {"type": gettype(args[1]), "value": getval(args[1])}

def createframe(args):
    
    frames["TF"] = {}
    
def pushframe(args):
    framecheck("TF")
    framestack.append(frames["TF"])
    frames.pop("TF")
    frames["LF"] = framestack[len(framestack)-1]

def popframe(args):
    framecheck("LF")
    frames["TF"] = frames["LF"]
    framestack.pop()
    if len(framestack) > 0:
        frames["LF"] = framestack[len(framestack)-1]
    else:
        frames.pop("LF")

def defvar(args):
    frame, name = getvar(args[0])
    framecheck(frame)
    if name in frames[frame]:
        sys.exit(52)
    frames[frame][name] = {"type": None, "value": None}
    
def call(args):
    global count, calls
    calls.append(count)
    tmp = list(filter(lambda name: name['label'] == args[0]["value"], labels))
    if not tmp:
        sys.exit(52)
    count = int(tmp[0]["order"])-1 

def returnfunc(args):
    global count, calls
    if not calls:
        sys.exit(56)
    count = calls.pop()
    
    
    
def pushs(args):
    if args[0]["type"] != "var":
        datastack.append({"type": args[0]["type"], "value": args[0]["value"]})
    else:
        frame, name = getvar(args[0])
        varcheck(frame, name)
        if frames[frame][name]["value"] == None:
            sys.exit(56)
        datastack.append({"type": frames[frame][name]["type"], "value": frames[frame][name]["value"]})
    
def pops(args):
    if len(datastack) == 0:
        sys.exit(56)
    frame, name = getvar(args[0])
    tmp = datastack.pop()
    varcheck(frame, name)
    frames[frame][name] = {"type": tmp["type"], "value": tmp["value"]}
    
def add(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "int" or gettype(args[2]) != "int":
        sys.exit(53)
    frames[frame][name] = {"type": 'int', "value": getval(args[1])+getval(args[2])}

def sub(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "int" or gettype(args[2]) != "int":
        sys.exit(53)
    frames[frame][name] = {"type": 'int', "value": getval(args[1])-getval(args[2])}

def mul(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "int" or gettype(args[2]) != "int":
        sys.exit(53)
    frames[frame][name] = {"type": 'int', "value": getval(args[1])*getval(args[2])}

def idiv(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "int" or gettype(args[2]) != "int":
        sys.exit(53)
    if getval(args[2]) == 0:
        sys.exit(57)
    frames[frame][name] = {"type": 'int', "value": getval(args[1])/getval(args[2])}

def lt(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != gettype(args[2]) or getval(args[1]) == "nil" or getval(args[2]) == "nil":
        sys.exit(53)
    if getval(args[1]) < getval(args[2]):
        frames[frame][name] = {"type": 'bool', "value": True}
    else:
        frames[frame][name] = {"type": 'bool', "value": False}

def gt(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != gettype(args[2]) or getval(args[1]) == "nil" or getval(args[2]) == "nil":
        sys.exit(53)
    if getval(args[1]) > getval(args[2]):
        frames[frame][name] = {"type": 'bool', "value": True}
    else:
        frames[frame][name] = {"type": 'bool', "value": False}

def eq(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "nil" and gettype(args[2]) != "nil":
        if gettype(args[1]) != gettype(args[2]):
            sys.exit(53)
    if getval(args[1]) == getval(args[2]):
        frames[frame][name] = {"type": 'bool', "value": True}
    else:
        frames[frame][name] = {"type": 'bool', "value": False}

def andfunc(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "bool" or gettype(args[2]) != "bool":
        sys.exit(53)
    if getval(args[1]) == "true":
        val1 = True
    else:
        val1 = False
    if getval(args[2]) == "true":
        val2 = True
    else:
        val2 = False 
    frames[frame][name] = {"type": 'bool', "value": val1 and val2}

def orfunc(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "bool" or gettype(args[2]) != "bool":
        sys.exit(53)
    if getval(args[1]) == "true":
        val1 = True
    else:
        val1 = False
    if getval(args[2]) == "true":
        val2 = True
    else:
        val2 = False 
    frames[frame][name] = {"type": 'bool', "value": val1 or val2}

def notfunc(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "bool":
        sys.exit(53)
    if getval(args[1]) == "true":
        val = True
    else:
        val = False
    frames[frame][name] = {"type": 'bool', "value": not val}

def int2char(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "int":
        sys.exit(53)
    try:
        val = chr(getval(args[1]))
    except:
        sys.exit(58)
    frames[frame][name] = {"type": 'string', "value": val}
    
def str2int(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "string" or gettype(args[2]) != "int":
        sys.exit(53)
    if getval(args[2]) < 0:
        sys.exit(58)
    try:
        val = ord(getval(args[1])[getval(args[2])])
    except:
        sys.exit(58)
    frames[frame][name] = {"type": 'int', "value": val}

def read(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "type":
        sys.exit(53)
    valtype = getval(args[1])
    val = inputfile.readline()
    val = val.rstrip("\n")
    if valtype == "int":
        try:
            val = int(val)
            frames[frame][name] = {"type": 'int', "value": val}
        except:
            frames[frame][name] = {"type": 'nil', "value": 'nil'}
    if valtype == "string":
        frames[frame][name] = {"type": 'string', "value": val}
    if valtype == "bool":
        if val.lower() == "true":
            frames[frame][name] = {"type": 'bool', "value": True}
        else:
            frames[frame][name] = {"type": 'bool', "value": False}
        
    
def write(args):
    if gettype(args[0]) == "bool":
        print(str(getval(args[0])).lower(), end='')
    elif gettype(args[0]) == "nil":
        print("", end='')
    else:
        print(str(getval(args[0])), end='')
    
def concat(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "string" or gettype(args[2]) != "string":
        sys.exit(53)
    frames[frame][name] = {"type": 'string', "value": getval(args[1]) + getval(args[2])}
    
def strlen(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "string":
        sys.exit(53)
    val = len(getval(args[1]))
    frames[frame][name] = {"type": 'int', "value": val}

def getchar(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[1]) != "string" or gettype(args[2]) != "int":
        sys.exit(53)
    if getval(args[2]) < 0:
        sys.exit(58)
    try:
        val = getval(args[1])[getval(args[2])]
    except:
        sys.exit(58)
    frames[frame][name] = {"type": 'string', "value": val}

def setchar(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if gettype(args[0]) != "string" or gettype(args[1]) != "int" or gettype(args[2]) != "string":
        sys.exit(53)
    string = getval(args[0])
    tmp = list(string)
    if getval(args[1]) < 0:
        sys.exit(58)
    try:
        tmp[getval(args[1])] = getval(args[2])[0]
    except:
        sys.exit(58)
    string = "".join(tmp)
    frames[frame][name] = {"type": 'string', "value": string}

def typefunc(args):
    frame, name = getvar(args[0])
    varcheck(frame, name)
    if args[1]["type"] == "var":
        frame2, name2 = getvar(args[1])
        varcheck(frame2, name2)
        if frames[frame2][name2]["value"] == None:
            frames[frame][name] = {"type": 'nil', "value": ''}
        else:
            frames[frame][name] = {"type": 'string', "value": gettype(args[1])}
    else:
        if getval(args[1]) == None:
            frames[frame][name] = {"type": 'nil', "value": ''}
        else:
            frames[frame][name] = {"type": 'string', "value": gettype(args[1])}

def label(args):
    pass

def jump(args):
    global count
    tmp = list(filter(lambda name: name['label'] == args[0]["value"], labels))
    if not tmp:
        sys.exit(52)
    count = int(tmp[0]["order"])-1     

def jumpifeq(args):
    global count
    tmp = list(filter(lambda name: name['label'] == args[0]["value"], labels))
    if not tmp:
        sys.exit(52)
    if (gettype(args[1]) == "nil") ^ (gettype(args[2]) == "nil"):
        return
    if gettype(args[1]) != gettype(args[2]):
        sys.exit(53)
    
    if getval(args[1]) == getval(args[2]):
        tmp = list(filter(lambda name: name['label'] == args[0]["value"], labels))
        if not tmp:
            sys.exit(52)
        count = int(tmp[0]["order"])-1

def jumpifneq(args):
    global count
    tmp = list(filter(lambda name: name['label'] == args[0]["value"], labels))
    if not tmp:
        sys.exit(52)
    if (gettype(args[1]) == "nil") ^ (gettype(args[2]) == "nil"):
        tmp = list(filter(lambda name: name['label'] == args[0]["value"], labels))
        if not tmp:
            sys.exit(52)
        count = int(tmp[0]["order"])-1
        return
    if gettype(args[1]) != gettype(args[2]):
        sys.exit(53)
    if getval(args[1]) != getval(args[2]):
        tmp = list(filter(lambda name: name['label'] == args[0]["value"], labels))
        if not tmp:
            sys.exit(52)
        count = int(tmp[0]["order"])-1

def exitfunc(args):
    if gettype(args[0]) != "int":
        sys.exit(53)
    if not (0 <= getval(args[0]) <= 49):
        sys.exit(57)
    sys.exit(getval(args[0]))

def dprint(args):
    pass

def breakfunc(args):
    pass
#---------------------------------------------------------------

# Pomocna struktura obsahujuca vsetky instrukcie jazyka IPPcode22 
# kazda instrukcia obsahuje argumenty a funkcie na interpretaciu
opcode = {"MOVE": {"args": ["var", "symb"], "function": move},
          "CREATEFRAME": {"args": [], "function": createframe},
          "PUSHFRAME": {"args": [], "function": pushframe},
          "POPFRAME": {"args": [], "function": popframe},
          "DEFVAR": {"args": ["var"], "function": defvar},
          "CALL": {"args": ["label"], "function": call},
          "RETURN": {"args": [], "function": returnfunc},
          "PUSHS": {"args": ["symb"], "function": pushs},
          "POPS": {"args": ["var"], "function": pops},
          "ADD": {"args": ["var", "symb", "symb"], "function": add},
          "SUB": {"args": ["var", "symb", "symb"], "function": sub},
          "MUL": {"args": ["var", "symb", "symb"], "function": mul},
          "IDIV": {"args": ["var", "symb", "symb"], "function": idiv},
          "LT": {"args": ["var", "symb", "symb"], "function": lt},
          "GT": {"args": ["var", "symb", "symb"], "function": gt},
          "EQ": {"args": ["var", "symb", "symb"], "function": eq},
          "AND": {"args": ["var", "symb", "symb"], "function": andfunc},
          "OR": {"args": ["var", "symb", "symb"], "function": orfunc},
          "NOT": {"args": ["var", "symb"], "function": notfunc},
          "INT2CHAR": {"args": ["var", "symb"], "function": int2char},
          "STRI2INT": {"args": ["var", "symb", "symb"], "function": str2int},
          "READ": {"args": ["var", "type"], "function": read},
          "WRITE": {"args": ["symb"], "function": write},
          "CONCAT": {"args": ["var", "symb", "symb"], "function": concat},
          "STRLEN": {"args": ["var", "symb"], "function": strlen},
          "GETCHAR": {"args": ["var", "symb", "symb"], "function": getchar},
          "SETCHAR": {"args": ["var", "symb", "symb"], "function": setchar},
          "TYPE": {"args": ["var", "symb"], "function": typefunc},
          "LABEL": {"args": ["label"], "function": label},
          "JUMP": {"args": ["label"], "function": jump},
          "JUMPIFEQ": {"args": ["label", "symb", "symb"], "function": jumpifeq},
          "JUMPIFNEQ": {"args": ["label", "symb", "symb"], "function": jumpifneq},
          "EXIT": {"args": ["symb"], "function": exitfunc},
          "DPRINT": {"args": ["symb"], "function": dprint},
          "BREAK": {"args": [], "function": breakfunc}}
#-----------------------------------------------------------------------------------------------------------------

# kontrola vstupnych argumentov
def argument_check(args):
    global inputfile, sourcefile
    if args.help:
        if len(sys.argv) > 2:
            sys.exit(10)
        print("Interpret pre jazyk IPPcode22")
        print("Pouzitie: [ --source=file | --input=file ]")
        print("    --source    | Vstupny XML subor jazyka IPPcode22")
        print("    --input     | Vstupny subor pre citanie pocas interpretacie")
        sys.exit(0)
        
    if(args.source == None and args.input == None):
        sys.exit(10)
    
    if args.source:
        try:
            sourcefile = open(args.source)
        except:
            sys.exit(11)
    
    if args.input:
        try:
            inputfile = open(args.input)
        except:
            sys.exit(11)
#-----------------------------------------------------------------------------------------------------------------

# spracovanie vstupneho XML subora a ulozenie jednotlivych instrukcii pre naslednu interpretaciu
def XML_check(args):
    try:
        tree = ET.parse(sourcefile)
        root = tree.getroot()
    except:
        sys.exit(31)
    
    if root.tag != "program":
        sys.exit(32)
        
    if("language" not in root.attrib):
        sys.exit(32)
    
    if(root.attrib["language"].lower() != "ippcode22"):
        sys.exit(32)
        
    for child in root:
        if child.tag != "instruction":
            sys.exit(32)
        
        if "opcode" not in child.attrib or "order" not in child.attrib:
            sys.exit(32)
        
        #kontrola ze je poradie instrukcie v spravnom tvare
        try:
            isint = int(child.attrib["order"])
        except:
            sys.exit(32)
        
        if int(child.attrib["order"]) <= 0:
            sys.exit(32)
        
        #duplicitne poradie
        if child.attrib["order"] in order:
            sys.exit(32)    
        order.append(child.attrib["order"])
        
        #kontrola ci sa nazov instrukcie nachadza v instrukcnej sade IPPcode22
        if child.attrib["opcode"].upper() not in opcode:
            sys.exit(32)
        count = 1
        arguments = []
        #zoradenie argumentov
        child[:] = sorted(child, key=lambda child: child.tag)
        for arg in child:
            if arg.tag != ("arg" + str(count)):
                sys.exit(32)
            
            if arg.text == None:
                arg.text = "" 
            
            if not arg_check(arg.attrib["type"], arg.text):
                sys.exit(32)
            
            #konvertovanie z hexa|octa
            if arg.attrib["type"] == "int":
                if "x" in arg.text or "X" in arg.text:
                    arg.text = int(arg.text, 0)
                elif "o" in arg.text or "O" in arg.text:
                    arg.text = int(arg.text, 0)
            
            if arg.attrib["type"] == "string":
                arg.text = re.sub('\\\\[0-9]{3}', escapeseq, arg.text)
             
            arguments.append({"type": arg.attrib["type"], "value": arg.text})
            count += 1
        #kontrola ci ma instrukcia spravny pocet argumentov
        if len(opcode[child.attrib["opcode"].upper()]["args"]) != len(arguments):
            sys.exit(32)
   
        #ulozenie instrukcie
        instructions.append({"instruction": child.attrib["opcode"].upper(), "args": arguments, "order": int(child.attrib["order"])})
        #zoradenie instrukcii podla poradia
        instructions.sort(key=lambda x: x["order"])
    return instructions

# Escape sekvenciu prekonvertuje na char
def escapeseq(match):
    return str(chr(int(match.group(0).replace("\\", ""))))

# Kontrola ze hodnota argumentu je validna    
def arg_check(argtype, argval):
    if argtype == "var":
        if re.match('^(LF|GF|TF)@?[a-zA-Z\-%!_?&$*][a-zA-Z\-%!@_&$?*0-9]*$', argval):
            return True  
    if argtype == "int":
        if  re.match('^(\+?\-?[0-9]+|0[xX][0-9a-fA-F]+|0[oO]?[0-7]+)$', argval):
            return True
          
    if argtype == "bool":
        if  re.match('^(true|false)$', argval):
            return True 
    if argtype == "string":
        if  re.match('^([^\\\\]*(\\\\[0-9]{3})*)*$', str(argval)):
            return True
          
    if argtype == "label":
        if  re.match('(^[a-zA-Z\-%!_&$*?][a-zA-Z\-%!_&$*?0-9]*$)', argval):
            return True
          
    if argtype == "nil":
        if  re.match('^nil$', argval):
            return True
          
    if argtype == "type":
        if  re.match('^nil$|^bool$|^string$|^int$', argval):
            return True
        
    return False            

def main():
    global count
    try:
        args = parser.parse_args()
    except:
        sys.exit(10)
    argument_check(args)
    
    code = XML_check(args)
    findlabels(code)
    while count < len(code):
        opcode[code[count]["instruction"]]["function"](code[count]["args"])
        count += 1
    sys.exit(0)

if __name__ == "__main__":
    main()
