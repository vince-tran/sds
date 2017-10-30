import rbac.acl
import rbac.context
from passlib.hash import pbkdf2_sha256

# Admin
isAdmin = False
adminPass = "pass" # ./server [PASSWORD]

# Accounts
accounts = {}

# Global Variables
dataDict = {}

# Output
output = []



####################################

class Principal:
    r = rbac.acl.Registry()
    context = rbac.context.IdentityContext(r)

    def __init__(self, name, password):
        ### CREATE PRINCIPAL ###
        if name in accounts:
            res = {"status": "FAILED"}
            output.append(res)
            return
        self.setName(name)
        hash = pbkdf2_sha256.hash(password)
        self._password = hash
        self.localVars = {}
        tmprole = self.r.add_role(name)
        self.context.set_roles_loader(tmprole)
        accounts.update({name: self})
        res = {"status": "CREATE_PRINCIPAL"}
        output.append(res)

    def setName(self, name):
        self._name = name

    def getName(self):
        return self._name

    def setPassword(self, user, password):
        ### CHANGE PASSWORD ###
        if user is not "admin" or user is not self._name or self._name is not accounts:
            res = {"status": "FAILED"}
            output.append(res)
            return
        else:
            hash = pbkdf2_sha256.hash(password)
            self._password = hash
            res = {"status": "CHANGE_PASSWORD"}
            output.append(res)

    def getPassword(self):
        return self._password

    def updatePermissions(self, user, var):
        self.r.allow(user, "read", var)
        self.r.allow(user, "write", var)
        self.r.allow(user, "append", var)
        self.r.allow(user, "delegate", var)

    def setData(self, var, d):
        ### SET ###
        if var not in dataDict:
            tmp = Variable(d)
            dataDict.update({var : tmp})
            self.r.add_resource(var)
            self.updatePermissions(self.getName(), var)
            self.updatePermissions("admin", var)
            res = {"status": "SET"}
            output.append(res)
        elif self.r.is_allowed(self.getName(), "write", var):
            res = {"status": "SET"}
            output.append(res)
        elif not self.r.is_allowed(self.getName(), "write", var):
            res = {"status": "FAILED"}
            output.append(res)

    def getData(self, var):
        if self.r.is_allowed(self.getName(), "read", var):
            if var in dataDict:
                return dataDict.get(var).varValue
            elif var in self.localVars:
                return self.localVars.get(var).varValue
        else:
            res = {"status": "FAILED"}
            output.append(res)


    def checkPermission(self, principal, action, resource):
        if self.r.is_allowed(principal, action, resource):
            res = {"status":"SUCCESS"}
            output.append(res)
        else:
            res = {"status":"DENIED"}
            output.append(res)

    def append(self, var, d):
        ### APPEND TO ###
        if self.r.is_allowed(self.getName(), "append", var) or self.r.is_allowed(self.getName(), "write", var):
            if var not in dataDict:
                res = {"status": "FAILED"}
                output.append(res)
                return
            if type(d) is str:
                if var in dataDict:
                    v = dataDict.get(var).varValue
                elif var in self.localVars:
                    v = self.localVars.get(var).varValue
                tmp = Variable(v + d)
                dataDict.update({var:tmp})
                self.r.add_resource(var)
            elif type(d) is dict:
                t = list(dataDict.get(var).varValue)
                t.append(d)
                tmp = Variable(t)
                dataDict.update({var:tmp})
                self.r.add_resource(var)
            res = {"status":"APPEND"}
            output.append(res)
        else:
            res = {"status": "DENIED"}
            output.append(res)

    def local(self, var, d):
        ### LOCAL ###
        if var in dataDict or var in self.localVars:
            res = {"status": "FAILED"}
            output.append(res)
            return
        if d in dataDict:
            t = dataDict.get(d).varValue
            tmp = Variable(t)
            self.localVars.update({var: tmp})
            self.r.add_resource(var)
            self.updatePermissions(self.getName(), var)
            self.updatePermissions("admin", var)
        else:
            tmp = Variable(d)
            self.localVars.update({var : tmp})
            self.r.add_resource(var)
            self.updatePermissions(self.getName(), var)
            self.updatePermissions("admin", var)
        res = {"status":"LOCAL"}
        output.append(res)

    def forEach(self, iterator, sequence, expression):
        ### FOREACH ###
        if self.r.is_allowed(self.getName(), "append", sequence) or self.r.is_allowed(self.getName(), "write", sequence):
            if not (sequence not in self.localVars or sequence not in dataDict):
                res = {"status": "FAILED"}
                output.append(res)
                return
            elif iterator in dataDict or iterator in self.localVars:
                res = {"status": "FAILED"}
                output.append(res)
                return

            if '.' in expression:
                seq = self.getData(sequence)
                expr = expression.split(".")
                if expr[0] == iterator:
                    for i,s in enumerate(seq):
                        seq[i] = s.get(expr[1])
                if sequence in dataDict:
                    tmp = Variable(seq)
                    dataDict.update({sequence: tmp})
                    print({sequence: tmp.varValue})
                    self.r.add_resource(sequence)
                else:
                    tmp = Variable(seq)
                    self.localVars.update({sequence: tmp})
                    print({sequence: tmp.varValue})
                    self.r.add_resource(sequence)
            else:
                seq = self.getData(expression)
                if sequence in dataDict:
                    tmp = Variable(seq)
                    dataDict.update({sequence: tmp})
                    print({sequence: tmp.varValue})
                    self.r.add_resource(sequence)
                else:
                    tmp = Variable(seq)
                    self.localVars.update({sequence: tmp})
                    print({sequence: tmp.varValue})
                    self.r.add_resource(sequence)
            res = {"status":"FOREACH"}
            output.append(res)
        else:
            res = {"status": "DENIED"}
            output.append(res)

    def setRights(self, principal, action, resource):
        ### SET DELEGATION ###
        if principal not in accounts:
            res = {"status": "FAILED"}
            output.append(res)
            return
        if resource == "all":
            for name in dataDict:
                print(name)
                self.r.allow(principal, action, name)
        else:
            self.r.allow(principal, action, resource)
        res = {"status": "SET_DELEGATION"}
        output.append(res)

    def deleteRights(self, principal, action, resource):
        ### DELETE DELEGATION ###
        if principal not in accounts:
            res = {"status": "FAILED"}
            output.append(res)
            return
        if self._name is not "admin":
            res = {"status": "DENIED"}
            output.append(res)
            return
        if principal == "all":
            for name in accounts:
                self.r.deny(name, action, resource)
        else:
            self.r.deny(principal, action, resource)
        res = {"status": "DELETE_DELEGATION"}
        output.append(res)

    def defaultRights(self, principal):
        ### DEFAULT DELEGATION ###
        if principal not in accounts:
            res = {"status": "FAILED"}
            output.append(res)
            return
        if self._name is not "admin":
            res = {"status": "DENIED"}
            output.append(res)
            return
        res = {"status": "DEFAULT_DELEGATOR"}
        output.append(res)

    def cmd_return(self, expr):
        ### RETURN ###
        if "\"" in expr:
            val = expr
        elif '.' in expr:
            e = expr.split('.')
            val = self.getData(expr[0]).get(e[1])
        else:
            val = self.getData(expr)
        res = {"status":"RETURNING", "output":val}
        output.append(res)

    def cmd_exit(self):
        ### EXIT ###
        if self._name == 'admin':
            res = {"status":"EXITING"}
            output.append(res)
            exit(0)
            # Terminate the client connection
            # Halts with return code 0
        else:
            res = {"status": "DENIED"}
            output.append(res)

####################################

class Variable:
    def __init__(self, val):
        self.varValue = val

    def __copy__(self):
        copiedVar = type(self)()
        copiedVar.__dict__.update(self.__dict__)
        return copiedVar

####################################

def verifyPass(principal, password):
    if pbkdf2_sha256.verify(password, principal.getPassword()):
        res = {"status":"SUCCESS"}
        output.append(res)
        return True
    else:
        res = {"stats":"DENIED"}
        output.append(res)
        return False

testPrincipal = Principal("admin","pass")
