import sys

from lark import Lark
from lark import Transformer

import logic
from logic import Principal
from logic import Variable
from logic import verifyPass
from logic import accounts
from logic import isAdmin
from logic import adminPass
from logic import output

class GrammarTransformer(Transformer):

	def prog0(self, param):
		p = param[0].children[0]
		s = param[1].children[0]
		cmds = param[2]
		return (p, s, cmds)

	def cmd0(self, param):
		return "cmd0"

	def cmd1(self, param):
		expr = param[0]
		return ("cmd1", expr)

	def cmd2(self, param):
		return param

	def expr0(self, param):
		value = param[0]
		return value

	def expr1(self, param):
		emptyList = []
		return emptyList

	def expr2(self, param):
		fieldvals = self.expr2Helper({}, param[0])
			
		return fieldvals
	
	def expr2Helper(self, dictionary, param):	
		fieldvals = dictionary
		valueTuple = param[0]
		x = str(valueTuple[0])
		value = str(valueTuple[1])

		tempDict = { x : value }
		fieldvals.update(tempDict)
		
		if(isinstance(param[1], list)):
			return self.expr2Helper(fieldvals, param[1])

		else:
			x2 = str(param[1][0])
			value2 = str(param[1][1])
			tempDict = { x2 : value2 }
			fieldvals.update(tempDict)
			return fieldvals

	def fieldvals0(self, param):
		x = param[0].children[0]
		value = param[1]
		return (x, value)

	def fieldvals1(self, param):
		fieldvals = []
		x = param[0].children[0]
		value = param[1]
		fieldvals.append((x, value))
		fieldvals.append(param[2])
		return fieldvals

	def value0(self, param):
		x = param[0].children[0]
		return x

	def value1(self, param):
		x = param[0].children[0]
		y = param[1].children[0]
		s = x + '.' + y
		return s

	def value2(self, param):
		s = param[0].children[0]
		return s

	def prim_cmd0(self, param):
		p = param[0].children[0]
		s = param[1].children[0]
		return ("prim_cmd0", p, s)

	def prim_cmd1(self, param):
		p = param[0].children[0]
		s = param[1].children[0]
		return ("prim_cmd1", p, s)

	def prim_cmd2(self, param):
		x = param[0].children[0]
		expr = param[1]
		return ("prim_cmd2", x, expr)

	def prim_cmd3(self, param):
		x = param[0].children[0]
		expr = param[1]
		return ("prim_cmd3", x, expr)

	def prim_cmd4(self, param):
		x = param[0].children[0]
		expr = param[1]
		return ("prim_cmd4", x, expr)

	def prim_cmd5(self, param):
		y = param[0].children[0]
		x = param[1].children[0]
		expr = param[2]
		return ("prim_cmd5", y, x, expr)

	def prim_cmd6(self, param):
		tgt = param[0]
		q = param[1].children[0]
		right = param[2]
		p = param[3].children[0]
		return ("prim_cmd6", tgt, q, right, p)

	def prim_cmd7(self, param):
		tgt = param[0]
		q = param[1].children[0]
		right = param[2]
		p = param[3].children[0]
		return ("prim_cmd7", tgt, q, right, p)

	def prim_cmd8(self, param):
		tgt = param[0]
		q = param[1].children[0]
		right = param[2]
		p = param[3].children[0]
		return ("prim_cmd8", tgt, q, right, p)

	def tgt0(self, param):
		return "all"

	def tgt1(self, param):
		tgt = param[0].children[0]
		return tgt

	def right0(self, param):
		return "read"

	def right1(self, param):
		return "write"

	def right2(self, param):
		return "append"

	def right3(self, param):
		return "delegate"


grammar = Lark(r"""
	prog		: "as" "principal" p "password" s "do" "\n" cmd "***"	-> prog0
	cmd 		: "exit" "\n" 						-> cmd0
				| "return" expr "\n"				-> cmd1
				| prim_cmd "\n" cmd 				-> cmd2
	expr		: value							-> expr0
				| "[]" 						-> expr1
				| "{" fieldvals "}"				-> expr2
	fieldvals	: x "=" value						-> fieldvals0
				| x "=" value "," fieldvals 			-> fieldvals1
	value		: x							-> value0
				| x "." y					-> value1
				| s 						-> value2
	prim_cmd	: "create" "principal" p s 				-> prim_cmd0
				| "change" "password" p s 			-> prim_cmd1
				| "set" x "=" expr 				-> prim_cmd2
				| "append" "to" x "with" expr 			-> prim_cmd3
				| "local" x "=" expr 				-> prim_cmd4
				| "foreach" y "in" x "replacewith" expr 	-> prim_cmd5
				| "set" "delegation" tgt q right "->" p 	-> prim_cmd6
				| "delete" "delegation" tgt q right "->" p 	-> prim_cmd7
				| "default" "delegator" "=" p 			-> prim_cmd8
	tgt 		: "all"							-> tgt0
				| x 						-> tgt1
	right 		: "read" 						-> right0
				| "write" 					-> right1
				| "append" 					-> right2
				| "delegate" 					-> right3
	p			: CNAME
	q			: CNAME
	s 			: ESCAPED_STRING
	x			: CNAME
	y			: CNAME

	%import common.WORD
	%import common.CNAME
	%import common.ESCAPED_STRING
	%import common.WS
	%ignore /[ \t\f\r]+/
	
	""", start='prog')


def messageHandler(text):
	tree = grammar.parse(text)
	transformer = GrammarTransformer()
	programData = transformer.transform(tree)
	return programExecuter(programData)

def programExecuter(programData):
	p = programData[0]
	s = programData[1]

	if(not(p in accounts)):
		return [{"status": "FAILED"}]
	elif(not(verifyPass(accounts.get(p), s))):
		print(p)
		print(s)
		print(accounts.get(p).getName())
		print("denied")
		return [{"status": "DENIED"}]
	else:
		functionCaller(programData[2])

def functionCaller(commands):
	cmd = commands[0]
	function = cmd[0]
	
	if(function == "cmd0"):
		print(function)
	elif(function == "cmd1"):
		print(function)
	elif(function == "prim_cmd0"):
		print(function)
	elif(function == "prim_cmd1"):
		print(function)
	elif(function == "prim_cmd2"):
		print(function)
	elif(function == "prim_cmd3"):
		print(function)
	elif(function == "prim_cmd4"):
		print(function)
	elif(function == "prim_cmd5"):
		print(function)
	elif(function == "prim_cmd6"):
		print(function)
	elif(function == "prim_cmd7"):
		print(function)
	elif(function == "prim_cmd8"):
		print(function)

	if(isinstance(commands[1], list)):
		return functionCaller(commands[1])
	else:
		function = commands[1][0]

	if(function == "cmd0"):
		print(function)
	elif(function == "cmd1"):
		print(function)

	

#--------------------------------------------------------------------------------



#print(grammar.parse('as principal admin password "admin" do \n set records = [] \n append to records with { name = "mike", date = "1-1-90" } \n append to records with { name = "dave", date = "1-1-85" } \n local names = records \n foreach rec in names replacewith rec.name \n return names \n ***').pretty())

#print('\n\n\n\n')

#tree = grammar.parse('as principal bob password "B0BPWxxd" do \n set z = "bobs string" \n set x = "another string" \n return x \n ***')

#tree = grammar.parse('as principal bob password "B0BPWxxd" do \n set x = "test string" \n set y = "test" \n set z = asd \n set delegation x mike read -> bob \n return x \n ***')

#tree = grammar.parse('as principal admin password "admin" do \n set records = [] \n append to records with { name = "mike", date = "1-1-90", sex = "male" } \n append to records with { name = "dave", date = "1-1-85", sex = "male", skin = "white" } \n local names = records \n foreach rec in names replacewith rec.name \n return names \n ***')

#tree = grammar.parse('as principal admin password "admin" do \n change password bob "gfhhfd" \n exit \n ***')

#print(GrammarTransformer().transform(tree))

