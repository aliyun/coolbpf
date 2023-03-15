use crate::builtin_function::BuiltinFunction;
use crate::types::*;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq)]
pub struct TranslationUnit {
    pub programs: Vec<BpfProgram>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BpfProgram {
    pub types: Vec<BpfProgramType>,
    pub statement: Statement,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DynKprobe {
    pub tn: TypeName,
    pub ident: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BpfProgramType {
    Begin,
    End,
    Interval(Duration),
    Kprobe(String),
    // (struct sock*, sk)
    DynKprobe(DynKprobe),
    Kretprobe(String),
    Tracepoint(String, String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CompoundStatement {
    pub statements: Vec<Statement>,
}

impl CompoundStatement {
    pub fn new() -> Self {
        CompoundStatement {
            statements: Vec::new(),
        }
    }

    pub fn push_statement(&mut self, statement: Statement) {
        self.statements.push(statement);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct IfStatement {
    pub condition: Box<Expression>,
    pub then_statement: Box<Statement>,
    pub else_statement: Option<Box<Statement>>,
}

impl IfStatement {
    pub fn new(condition: Expression, then_statement: Statement) -> Self {
        IfStatement {
            condition: Box::new(condition),
            then_statement: Box::new(then_statement),
            else_statement: None,
        }
    }

    pub fn set_else_statement(&mut self, else_statement: Statement) {
        self.else_statement = Some(Box::new(else_statement));
    }
}

/// Statement.
#[derive(Clone, Debug, PartialEq)]
pub enum Statement {
    Compound(Box<CompoundStatement>),
    Expression(ExpressionStatement),
    If(IfStatement),
    Return,
}

/// Expression statement.
pub type ExpressionStatement = Option<Expression>;

#[derive(Clone, Debug, PartialEq)]
pub enum UnaryOperator {
    /// `operand++`
    PostIncrement,
    /// `operand--`
    PostDecrement,
    /// `++operand`
    PreIncrement,
    /// `--operand`
    PreDecrement,
    /// `&operand`
    Address,
    /// `*operand`
    Indirection,
    /// `+operand`
    Plus,
    /// `-operand`
    Minus,
    /// `~operand`
    Complement,
    /// `!operand`
    Negate,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BinaryOp {
    /// `lhs[rhs]`
    Index,
    Or,
    Xor,
    And,
    BitOr,
    BitXor,
    BitAnd,
    Equal,
    NonEqual,
    LT,
    GT,
    LTE,
    GTE,
    LShift,
    RShift,
    Add,
    Sub,
    Mult,
    Div,
    Mod,

    Assign,
}

pub type StringLiteral = String;

#[derive(Clone, Debug, PartialEq)]
pub struct CallExpression {
    pub callee: BuiltinFunction,
    pub arguments: Vec<Expression>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MemberExpression {
    pub expression: Box<Expression>,
    pub identifier: Identifier,
}

impl MemberExpression {
    pub fn new(expression: Expression, identifier: Identifier) -> Self {
        MemberExpression {
            expression: Box::new(expression),
            identifier,
        }
    }
}

impl Into<Expression> for MemberExpression {
    fn into(self) -> Expression {
        Expression::Member(self)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeSpecifier {
    Void,
    Char,
    Bool,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    String,
    Pointer,
    Struct,
    Union,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TypeName {
    pub type_specifier: TypeSpecifier,
    pub pointers: usize,
    pub identifier: Option<Identifier>,
}

// (type) cast
#[derive(Clone, Debug, PartialEq)]
pub struct CastExpression {
    // only support direct(.) opertator
    pub type_name: TypeName,
    pub expression: Box<Expression>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BinaryExpression {
    pub op: BinaryOp,
    pub left: Box<Expression>,
    pub right: Box<Expression>,
}

impl BinaryExpression {
    pub fn new(op: BinaryOp, left: Expression, right: Expression) -> Self {
        BinaryExpression {
            op,
            left: Box::new(left),
            right: Box::new(right),
        }
    }
}

impl From<BinaryExpression> for Expression {
    fn from(b: BinaryExpression) -> Self {
        Expression::Binary(b)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UnaryExpression {
    pub operator: UnaryOperator,
    pub operand: Box<Expression>,
}

impl From<UnaryExpression> for Expression {
    fn from(b: UnaryExpression) -> Self {
        Expression::Unary(b)
    }
}

impl UnaryExpression {
    pub fn new(operator: UnaryOperator, operand: Expression) -> Self {
        UnaryExpression {
            operator,
            operand: Box::new(operand),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expression {
    Identifier(Identifier),
    Constant(Constant),
    StringLiteral(StringLiteral),
    /// Integral constant expression.
    IntConst(i32),
    /// Unsigned integral constant expression.
    UIntConst(u32),
    LongConst(i64),
    ULongConst(u64),
    /// Boolean constant expression.
    BoolConst(bool),
    /// A unary expression, gathering a single expression and a unary operator.
    Unary(UnaryExpression),
    /// A binary expression, gathering two expressions and a binary operator.
    // Binary(BinaryOp, Box<Expression>, Box<Expression>),
    Binary(BinaryExpression),
    Cast(CastExpression),
    /// A ternary conditional expression, gathering three expressions.
    Ternary(Box<Expression>, Box<Expression>, Box<Expression>),
    Call(CallExpression),
    Member(MemberExpression),
    /// Post-incrementation of an expression.
    PostInc(Box<Expression>),
    /// Post-decrementation of an expression.
    PostDec(Box<Expression>),

    /// An expression that contains several, separated with comma.
    Comma(Box<Expression>, Box<Expression>),
}
