<?php
ini_set('display_errors', 'stderr');

$order = 0;
$header = false;

//kontrola vstupu, vypis help
if($argc > 1){
    if($argv[1] == "--help"){
        if($argc > 2){
            exit(10);
        }
        echo("\t\tSkript typu filter parse.php nacita zo standardneho vstupu zdrojovy kod v IPPcode22,
              zkontroluje lexikalnu a syntakticku spravnost kodu a vypise na standardni vystup XML reprezentaciu.
              Tento skript bude pracovat s tymto parametrom:
              --help vypise napovedu skriptu.
              Chybove navratove hodnoty specificke pre analyzator:
              21 - chybna alebo chybajuca hlavicka v zdrojovom kode zapisanom v IPPcode22;
              22 - neznamy alebo chybny operacny kod v zdrojovom kode zapisanom v IPPcode22;
              23 - ina lexikalna alebo syntakticka chyba zdrojoveho kodu zapisanom v IPPcode22.\n");
        exit(0);
    }
}

echo("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

//cyklus nacitava po jednom riadku zo STDIN a analyzuje zdrojovy kod
while($line = fgets(STDIN)){
    //osetrenie komentarov, medzier, tabulatorov a rozdelenie nacitaneho riadka na jednotlive slova
    $line = preg_replace("/( #.*|#.*)/", "", $line);
    $line = preg_replace('/\s+/', ' ', $line);
    $split = explode(' ', trim($line, " \t\n"));
    
    //kontrola hlavicky
    if(!$header){
        if (preg_match("/^.IPPcode22$/i", $split[0])){
            $header = true;
            echo("<program language=\"IPPcode22\">\n");
            continue;
        }
        else if($split[0] == "")
            continue;
        else
            exit(21);
    }

    //instrukcie na velke pismena
    $opcode = strtoupper($split[0]);
    //pocet slov v riadku
    $count = count($split);

    //switch kontrolujuci prve slovo v riadku porovnanva s instrukciami
    switch(strtoupper($split[0])){
        case 'CREATEFRAME':
        case 'PUSHFRAME':
        case 'RETURN':
        case 'BREAK':
        case 'POPFRAME':
            if($count == 1){
            $order++;
            echo("\t<instruction order=\"$order\" opcode=\"$opcode\"/>\n");
            }
            else
                exit(23);
            break;
        case 'DEFVAR':
        case 'PUSHS':
        case 'WRITE':
        case 'EXIT':
        case 'DPRINT':
            if($count == 2){
            $order++;
            echo("\t<instruction order=\"$order\" opcode=\"$opcode\">\n");
            symbol_check($split[1], 1);
            echo("\t</instruction>\n");
            }
            else
                exit(23);
            break;
        case 'CALL':
        case 'LABEL':
        case 'JUMP':
            if($count == 2){
            $order++;
            echo("\t<instruction order=\"$order\" opcode=\"$opcode\">\n");
            label_check($split[1]);
            echo("\t</instruction>\n");
            }
            else
                exit(23);
            break;
        case 'MOVE':
        case 'INT2CHAR':
        case 'STRLEN':
        case 'TYPE':
        case 'NOT':
            if($count == 3){
            $order++;
            echo("\t<instruction order=\"$order\" opcode=\"$opcode\">\n");
            var_check($split[1], 1);
            symbol_check($split[2], 2);
            echo("\t</instruction>\n");
            }
            else
                exit(23);
            break;
        case 'ADD':
        case 'SUB':
        case 'MUL':
        case 'IDIV':
        case 'LT':
        case 'GT':
        case 'EQ':
        case 'AND':
        case 'OR':
        case 'STRI2INT':
        case 'CONCAT':
        case 'GETCHAR':
        case 'SETCHAR':
            if($count == 4){
            $order++;
            echo("\t<instruction order=\"$order\" opcode=\"$opcode\">\n");
            var_check($split[1], 1);
            symbol_check($split[2], 2);
            symbol_check($split[3], 3);
            echo("\t</instruction>\n");
            }
            else 
                exit(23);
            break;
        case 'JUMPIFEQ':
        case 'JUMPIFNEQ':
            if($count == 4){
            $order++;
            echo("\t<instruction order=\"$order\" opcode=\"$opcode\">\n");
            label_check($split[1]);
            symbol_check($split[2], 2);
            symbol_check($split[3], 3);
            echo("\t</instruction>\n");
            }
            else
                exit(23);
            break;
        case 'READ':
            if($count == 3){
            $order++;
            echo("\t<instruction order=\"$order\" opcode=\"READ\">\n");
            if($count == 2){
                var_check($split[1], 1);
                echo("\t\t<arg2 type=\"nil\"></arg2>\n");
            }
            else{
                var_check($split[1], 1);
                type_check($split[2]);
            }
            echo("\t</instruction>\n");
            }
            else
                exit(23);      
            break;
        case 'POPS':
            if($count == 2){
                $order++;
                echo("\t<instruction order=\"$order\" opcode=\"POPS\">\n");
                var_check($split[1], 1);
                echo("\t</instruction>\n");
            }
            else
                exit(23);
            break;
        default:
            if($split[0] !== "")
                exit(22);       
    }
}

echo("</program>\n");

//funkcia kontrolujucu spravnost variable argumentu
function var_check($var, $argcounter){
    if(preg_match("/^(LF|GF|TF)@?[a-zA-Z\-%!_?&$*][a-zA-Z\-%!@_&$?*0-9]*$/", $var)){
        $var = str_replace("&", "&amp;", $var);
        $var = str_replace("<", "&lt;", $var);
        $var = str_replace(">", "&gt;", $var);
        echo("\t\t<arg$argcounter type=\"var\">$var</arg$argcounter>\n");
    }
    else
        exit(23);
}

//funkcia zistujuca druh symbolu v argumente
function symbol_check($symbol, $argcounter){
    if(preg_match("/string/", $symbol))
        string_check($symbol, $argcounter);
    else if(preg_match("/int/", $symbol))
        int_check($symbol, $argcounter);
    else if(preg_match("/bool/", $symbol))
        bool_check($symbol, $argcounter);
    else if(preg_match("/nil/", $symbol))
        nil_check($symbol, $argcounter);
    else
        var_check($symbol, $argcounter);
}

//funkcia kontrolujuca argument label
function label_check($label){
    if(preg_match("/(^[a-zA-Z\-%!_&$*?][a-zA-Z\-%!_&$*?0-9]*$)/", $label))
        echo("\t\t<arg1 type=\"label\">$label</arg1>\n");
    else
        exit(23);
}

//funkcia kontrolujuca argument type
function type_check($type){
    if(preg_match("/^string$/", $type))
        echo("\t\t<arg2 type=\"type\">string</arg2>\n");
    else if(preg_match("/^int$/", $type))
        echo("\t\t<arg2 type=\"type\">int</arg2>\n");
    else if(preg_match("/^bool$/", $type))
        echo("\t\t<arg2 type=\"type\">bool</arg2>\n");
    else
        exit(23);
}

//funkcia kontrolujuca argument int
function int_check($int, $argcounter){
    if(preg_match("/^int@(\+?\-?[0-9]+|0[xX][0-9a-fA-F]+|0[oO]?[0-7]+)$/", $int))
        echo("\t\t<arg$argcounter type=\"int\">".substr($int, 4)."</arg$argcounter>\n");
    else
        exit(23);
}

//funkcia kontrolujuca argument string
function string_check($string, $argcounter){
    if(preg_match("/^string@([^\\\\]*(\\\\[0-9]{3})*)*$/", $string)){
        $string = str_replace("&", "&amp;", $string);
        $string = str_replace("<", "&lt;", $string);
        $string = str_replace(">", "&gt;", $string);
        echo("\t\t<arg$argcounter type=\"string\">".substr($string, 7)."</arg$argcounter>\n");
    }
    else
        exit(23);
}

//funkcia kontrolujuca argument bool
function bool_check($bool, $argcounter){
    if(preg_match("/^bool@(true|false)$/", $bool))
        echo("\t\t<arg$argcounter type=\"bool\">".substr($bool, 5)."</arg$argcounter>\n");
    else
        exit(23);
}

//funkcia kontrolujuca argument nil
function nil_check($nil, $number){
    if(preg_match("/^nil@nil$/", $nil))
        echo("\t\t<arg$number type=\"nil\">".substr($nil, 4)."</arg$number>\n");
    else   
        exit(23);
}

?>