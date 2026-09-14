import java

/** A source-backed Java element retained in the Phase 7 program graph. */
class Phase7ProgramNode extends Element {
  Phase7ProgramNode() {
    this.fromSource() and
    (
      this instanceof Callable or
      this instanceof Type or
      this instanceof Call or
      this instanceof VarAccess or
      this instanceof VariableUpdate or
      this instanceof ReturnStmt or
      this instanceof ThrowStmt or
      this instanceof ConditionalStmt or
      this instanceof BlockStmt
    )
  }

  string getNodeKind() {
    this instanceof Expr and result = "EXPR"
    or
    this instanceof Stmt and result = "STMT"
    or
    this instanceof Callable and result = "CALLABLE"
    or
    this instanceof Type and result = "TYPE"
  }

  string getSubkind() { result = this.getAPrimaryQlClass() }

  string getSymbol() {
    exists(Callable callable | this = callable | result = callable.getName())
    or
    exists(VarAccess access | this = access | result = access.getVariable().getName())
    or
    exists(MethodCall call | this = call | result = call.getMethod().getName())
    or
    exists(MethodCall call | this = call and not exists(call.getMethod()) | result = "")
    or
    exists(Type type | this = type | result = type.getName())
    or
    not this instanceof Callable and
    not this instanceof VarAccess and
    not this instanceof MethodCall and
    not this instanceof Type and
    result = ""
  }

  string getTypeName() {
    exists(Expr expression | this = expression | result = expression.getType().getName())
    or
    exists(Expr expression | this = expression and not exists(expression.getType()) | result = "")
    or
    exists(Callable callable | this = callable | result = callable.getReturnType().getName())
    or
    exists(Type type | this = type | result = type.getName())
    or
    not this instanceof Expr and
    not this instanceof Callable and
    not this instanceof Type and
    result = ""
  }
}

predicate phase7AstEdge(Phase7ProgramNode source, Phase7ProgramNode target) {
  target.(Expr).getParent() = source
  or
  target.(Stmt).getParent() = source
}

predicate phase7CallEdge(Phase7ProgramNode source, Phase7ProgramNode target) {
  exists(Call call |
    source = call and
    target = call.getCallee().getSourceDeclaration()
  )
}

predicate phase7ControlDependencyEdge(Phase7ProgramNode source, Phase7ProgramNode target) {
  exists(IfStmt conditional |
    source = conditional.getCondition() and
    (target = conditional.getThen() or target = conditional.getElse())
  )
  or
  exists(ForStmt loop | source = loop.getCondition() and target = loop.getBody())
  or
  exists(WhileStmt loop | source = loop.getCondition() and target = loop.getBody())
  or
  exists(DoStmt loop | source = loop.getCondition() and target = loop.getBody())
}

predicate phase7TypeEdge(Phase7ProgramNode source, Phase7ProgramNode target) {
  source.(Expr).getType() = target.(Type)
  or
  target.(Callable).getDeclaringType() = source.(Type)
}
