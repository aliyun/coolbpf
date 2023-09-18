use crate::call::Call;
use crate::constant::Constant;
use crate::lexer::Token;
use crate::lexer::Tokens;
use anyhow::bail;
use anyhow::Result;
use bpfir::types::BinaryOp;
use bpfir::types::UnaryOp;
use bpfir::Type;
use bpfir::TypeKind;
use logos::Span;

#[derive(Clone, Debug, PartialEq)]
pub struct MemberAttr {
    pub offset: u32,          // in bytes
    pub bitfield_offset: u16, // in bits
    pub bitfield_size: u16,   // in bits
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExprKind {
    Compound(Vec<Expr>), // compound statement
    ExprStmt(Box<Expr>),
    If(Box<Expr>, Box<Expr>, Box<Option<Expr>>), // condition, then, else
    Return,

    Type(Type),

    Ident(String),  // identifier
    LitStr(String), // string literal
    Constant(i64),
    Unary(UnaryOp, Box<Expr>),              // unary expression
    Binary(BinaryOp, Box<Expr>, Box<Expr>), // binary expression
    Cast(Box<Expr>, Box<Expr>),
    Call(Call, Vec<Expr>),
    Member(Box<Expr>, Box<Expr>, Option<MemberAttr>), //member access
    Trace(Box<Expr>, Box<Expr>), // bpf program, tracing point definition and program body
}

#[derive(Clone, Debug, PartialEq)]
pub struct Expr {
    pub kind: ExprKind,
    pub span: Span,
    pub ty: Type,
}

impl Expr {
    pub fn new(kind: ExprKind, span: Span) -> Self {
        Self {
            kind,
            span,
            ty: Type::new(TypeKind::Undef),
        }
    }

    pub fn from_compound(compound: Vec<Expr>, span: Span) -> Self {
        Self::new(ExprKind::Compound(compound), span)
    }

    pub fn from_exprstmt(stmt: Expr, span: Span) -> Self {
        Self::new(ExprKind::ExprStmt(Box::new(stmt)), span)
    }

    pub fn from_if(c: Expr, t: Expr, e: Option<Expr>, span: Span) -> Self {
        Self::new(ExprKind::If(Box::new(c), Box::new(t), Box::new(e)), span)
    }
    pub fn from_return(span: Span) -> Self {
        Self::new(ExprKind::Return, span)
    }
    pub fn new_type(ty: Type, span: Span) -> Self {
        Self::new(ExprKind::Type(ty), span)
    }

    pub fn from_trace(types: Vec<Expr>, program: Expr, span: Span) -> Self {
        Self::new(
            ExprKind::Trace(Box::new(types[0].clone()), Box::new(program)),
            span,
        )
    }

    pub fn new_cast(cast: Expr, ty: Expr, span: Span) -> Self {
        Self::new(ExprKind::Cast(Box::new(cast), Box::new(ty)), span)
    }

    pub fn new_constant(c: Constant, span: Span) -> Self {
        let mut expr = Self::new(ExprKind::Constant(c.value()), span);
        expr.ty = c.ty().clone();
        expr
    }

    pub fn new_binary(op: BinaryOp, l: Expr, r: Expr, span: Span) -> Self {
        Self::new(ExprKind::Binary(op, Box::new(l), Box::new(r)), span)
    }

    pub fn new_unary(op: UnaryOp, e: Expr, span: Span) -> Self {
        Self::new(ExprKind::Unary(op, Box::new(e)), span)
    }

    pub fn new_ident(ident: String, span: Span) -> Self {
        Self::new(ExprKind::Ident(ident), span)
    }

    pub fn new_litstr(str: String, span: Span) -> Self {
        Self::new(ExprKind::LitStr(str), span)
    }

    pub fn new_call(call: Call, args: Vec<Expr>, span: Span) -> Self {
        Self::new(ExprKind::Call(call, args), span)
    }

    pub fn new_member(expr1: Expr, expr2: Expr, span: Span) -> Self {
        Self::new(
            ExprKind::Member(Box::new(expr1), Box::new(expr2), None),
            span,
        )
    }

    pub fn ty(&self) -> &Type {
        &self.ty
    }
}

macro_rules! parsed_debug {
    ($tokens: ident, $left: expr, $right: expr) => {
        let span = merge_span($left, $right);
        log::debug!("Parsed expression: {}", $tokens.span_string(span));
    };
}

fn merge_span(left: &Span, right: &Span) -> Span {
    let mut span = Span::default();
    span.start = left.start;
    span.end = right.end;
    span
}

fn type_expression(tokens: &mut Tokens) -> Result<Expr> {
    let mut ty = match tokens.read() {
        Token::Bool => Type::bool(),
        Token::Char => Type::char(),
        Token::I8 => Type::i8(),
        Token::U8 => Type::u8(),
        Token::I16 => Type::i16(),
        Token::U16 => Type::u16(),
        Token::I32 => Type::i32(),
        Token::U32 => Type::u32(),
        Token::I64 => Type::i64(),
        Token::U64 => Type::u64(),
        Token::Struct => Type::struct_(tokens.eat_identifier()?),
        Token::Union => Type::union(tokens.eat_identifier()?),
        _ => todo!(),
    };

    while tokens.try_eat(Token::Star) {
        ty = Type::ptr(ty);
    }

    tokens.eat(Token::RightParen)?;

    return Ok(Expr::new_type(ty, tokens.span()));
}

///
/// ```grammar
/// postfix_expression
/// 	: primary_expression
/// 	| postfix_expression '[' expression ']'
/// 	| postfix_expression '(' ')'
/// 	| postfix_expression '(' argument_expression_list ')'
/// 	| postfix_expression '.' IDENTIFIER
/// 	| postfix_expression PTR_OP IDENTIFIER
/// 	| postfix_expression INC_OP
/// 	| postfix_expression DEC_OP
/// 	;
/// ```
pub fn postfix_expression(tokens: &mut Tokens) -> Result<Expr> {
    let mut rename_expression = primary_expression(tokens)?;

    // if tokens.try_eat(Token::LeftBracket) {
    // [] operator
    // }

    loop {
        let base = tokens.span();

        if tokens.try_eat(Token::LeftBracket) {
            let expression = expression(tokens)?;

            tokens.eat(Token::RightBracket)?;

            rename_expression = Expr::new_binary(
                BinaryOp::Index,
                rename_expression,
                expression,
                merge_span(&base, &tokens.span()),
            );
            continue;
        }

        // member expression
        if tokens.try_eat(Token::Dot) {
            rename_expression = Expr::new_member(
                rename_expression,
                Expr::new_ident(tokens.eat_identifier()?, tokens.span()),
                merge_span(&base, &tokens.span()),
            );
            continue;
        }

        if tokens.try_eat(Token::Deref) {
            // replace "->" with an unary expression
            rename_expression = Expr::new_unary(
                UnaryOp::Deref,
                rename_expression,
                merge_span(&base, &tokens.span()),
            );
            rename_expression = Expr::new_member(
                rename_expression,
                Expr::new_ident(tokens.eat_identifier()?, tokens.span()),
                merge_span(&base, &tokens.span()),
            );
            continue;
        }

        return Ok(rename_expression);
    }
}

///
///
///
/// CFG grammar:
///
/// ```
/// primary_expression
///	    : IDENTIFIER
///	    | CONSTANT
///	    | STRING_LITERAL
///	    | '(' expression ')'
///	    ;
/// ```
pub fn primary_expression(tokens: &mut Tokens) -> Result<Expr> {
    let base = tokens.span();

    if tokens.try_eat(Token::LeftParen) {
        let expression = expression(tokens);
        tokens.eat(Token::RightParen)?;
        return expression;
    }

    match tokens.read() {
        Token::Identifier(i) => {
            if let Ok(func) = Call::try_from(i.as_str()) {
                if tokens.try_eat(Token::LeftParen) {
                    return Ok(Expr::new_call(
                        func,
                        argument_expression_list(tokens)?,
                        merge_span(&base, &tokens.span()),
                    ));
                }
            }

            return Ok(Expr::new_ident(
                i.clone(),
                merge_span(&base, &tokens.span()),
            ));
        }
        Token::Constant(c) => Ok(Expr::new_constant(c, merge_span(&base, &tokens.span()))),
        // Token::
        Token::StringLiteral(s) => Ok(Expr::new_litstr(s, merge_span(&base, &tokens.span()))),
        _ => bail!("wrong params {:?}", tokens),
    }
}

/// ```grammar
/// argument_expression_list
/// 	: assignment_expression
/// 	| argument_expression_list ',' assignment_expression
/// 	;
/// ```
pub fn argument_expression_list(tokens: &mut Tokens) -> Result<Vec<Expr>> {
    let _ = tokens.span();

    if tokens.try_eat(Token::RightParen) {
        return Ok(vec![]);
    }
    let mut args = Vec::new();
    args.push(assignment_expression(tokens)?);
    while tokens.try_eat(Token::Comma) {
        args.push(assignment_expression(tokens)?);
    }
    tokens.eat(Token::RightParen)?;
    return Ok(args);
}

///```grammar
/// multiplicative_expression
/// 	: cast_expression
/// 	| multiplicative_expression '*' cast_expression
/// 	| multiplicative_expression '/' cast_expression
/// 	| multiplicative_expression '%' cast_expression
/// 	;
/// ```
pub fn multiplicative_expression(tokens: &mut Tokens) -> Result<Expr> {
    let base = tokens.span();
    let mut expression = cast_expression(tokens)?;

    loop {
        if tokens.try_eat(Token::Star) {
            expression = Expr::new_binary(
                BinaryOp::Mult,
                expression,
                cast_expression(tokens)?,
                merge_span(&base, &tokens.span()),
            );
        } else if tokens.try_eat(Token::Slash) {
            expression = Expr::new_binary(
                BinaryOp::Div,
                expression,
                cast_expression(tokens)?,
                merge_span(&base, &tokens.span()),
            );
        } else {
            return Ok(expression);
        }
    }
}

///
/// ```grammar
/// additive_expression
///	    : multiplicative_expression
///	    | additive_expression '+' multiplicative_expression
///	    | additive_expression '-' multiplicative_expression
///	    ;
/// ```
///
pub fn additive_expression(tokens: &mut Tokens) -> Result<Expr> {
    let base = tokens.span();
    let mut expression = multiplicative_expression(tokens)?;
    loop {
        if tokens.try_eat(Token::Plus) {
            expression = Expr::new_binary(
                BinaryOp::Add,
                expression,
                multiplicative_expression(tokens)?,
                merge_span(&base, &tokens.span()),
            );
        } else if tokens.try_eat(Token::Minus) {
            expression = Expr::new_binary(
                BinaryOp::Sub,
                expression,
                multiplicative_expression(tokens)?,
                merge_span(&base, &tokens.span()),
            );
        } else {
            return Ok(expression);
        }
    }
}

///
/// ```grammar
/// unary_expression
///	    : postfix_expression
///	    | INC_OP unary_expression
///	    | DEC_OP unary_expression
///	    | unary_operator cast_expression
///	    | SIZEOF unary_expression
///	    | SIZEOF '(' type_name ')'
///	    ;
/// ```
///
///
pub fn unary_expression(tokens: &mut Tokens) -> Result<Expr> {
    let base = tokens.span();
    if tokens.try_eat(Token::Plus) {
        return cast_expression(tokens);
    }

    if tokens.try_eat(Token::Minus) {
        return Ok(Expr::new_unary(
            UnaryOp::Neg,
            cast_expression(tokens)?,
            merge_span(&base, &tokens.span()),
        ));
    }

    if tokens.try_eat(Token::Star) {
        return Ok(Expr::new_unary(
            UnaryOp::Deref,
            cast_expression(tokens)?,
            merge_span(&base, &tokens.span()),
        ));
    }

    return postfix_expression(tokens);
}

///```grammar
/// cast_expression
///	    : unary_expression
/// 	| '(' type_name ')' cast_expression
/// 	;
/// ```
pub fn cast_expression(tokens: &mut Tokens) -> Result<Expr> {
    let base = tokens.span();

    if tokens.peek() == Token::LeftParen && tokens.peek_offset(1).is_type_name() {
        tokens.eat(Token::LeftParen)?;
        let ty = type_expression(tokens)?;

        return Ok(Expr::new_cast(
            cast_expression(tokens)?,
            ty,
            merge_span(&base, &tokens.span()),
        ));
    }

    return unary_expression(tokens);
}

///
/// ```grammar
/// equality_expression
///	    : relational_expression
///	    | equality_expression EQ_OP relational_expression
///	    | equality_expression NE_OP relational_expression
///	    ;
/// ```
pub fn equality_expression(tokens: &mut Tokens) -> Result<Expr> {
    let base = tokens.span();
    let expression = relational_expression(tokens)?;

    if tokens.try_eat(Token::TwoEqual) {
        return Ok(Expr::new_binary(
            BinaryOp::Equal,
            expression,
            relational_expression(tokens)?,
            merge_span(&base, &tokens.span()),
        ));
    }

    if tokens.try_eat(Token::NotEqual) {
        return Ok(Expr::new_binary(
            BinaryOp::NonEqual,
            expression,
            relational_expression(tokens)?,
            merge_span(&base, &tokens.span()),
        ));
    }
    return Ok(expression);
}

///
/// ```grammar
/// relational_expression
///	    : shift_expression
///	    | relational_expression '<' shift_expression
///	    | relational_expression '>' shift_expression
///	    | relational_expression LE_OP shift_expression
///	    | relational_expression GE_OP shift_expression
///	;
/// ```
pub fn relational_expression(tokens: &mut Tokens) -> Result<Expr> {
    let base = tokens.span();
    let expression = shift_expression(tokens)?;

    if tokens.try_eat(Token::LessThan) {
        return Ok(Expr::new_binary(
            BinaryOp::LT,
            expression,
            shift_expression(tokens)?,
            merge_span(&base, &tokens.span()),
        ));
    }

    if tokens.try_eat(Token::GreaterThan) {
        return Ok(Expr::new_binary(
            BinaryOp::GT,
            expression,
            shift_expression(tokens)?,
            merge_span(&base, &tokens.span()),
        ));
    }

    if tokens.try_eat(Token::LessThanEqual) {
        return Ok(Expr::new_binary(
            BinaryOp::LTE,
            expression,
            shift_expression(tokens)?,
            merge_span(&base, &tokens.span()),
        ));
    }

    if tokens.try_eat(Token::GreaterThanEqual) {
        return Ok(Expr::new_binary(
            BinaryOp::GTE,
            expression,
            shift_expression(tokens)?,
            merge_span(&base, &tokens.span()),
        ));
    }

    return Ok(expression);
}

///
/// ```grammar
/// shift_expression
///	    : additive_expression
///	    | shift_expression LEFT_OP additive_expression
///	    | shift_expression RIGHT_OP additive_expression
///	    ;
/// ```
pub fn shift_expression(tokens: &mut Tokens) -> Result<Expr> {
    let base = tokens.span();
    let expression = additive_expression(tokens)?;

    if tokens.try_eat(Token::LShift) {
        return Ok(Expr::new_binary(
            BinaryOp::LShift,
            expression,
            additive_expression(tokens)?,
            merge_span(&base, &tokens.span()),
        ));
    }

    if tokens.try_eat(Token::RShift) {
        return Ok(Expr::new_binary(
            BinaryOp::RShift,
            expression,
            additive_expression(tokens)?,
            merge_span(&base, &tokens.span()),
        ));
    }
    return Ok(expression);
}

///```grammar
/// assignment_expression
///	    : conditional_expression
///	    | unary_expression assignment_operator assignment_expression
///	    ;
/// ```
pub fn assignment_expression(tokens: &mut Tokens) -> Result<Expr> {
    let base = tokens.span();
    let expression = equality_expression(tokens)?;

    if tokens.try_eat(Token::Equal) {
        return Ok(Expr::new_binary(
            BinaryOp::Assign,
            expression,
            assignment_expression(tokens)?,
            merge_span(&base, &tokens.span()),
        ));
    }
    return Ok(expression);
}

///
/// ```grammar
/// expression
///	    : assignment_expression
///	    | expression ',' assignment_expression
///	    ;
/// ```
pub fn expression(tokens: &mut Tokens) -> Result<Expr> {
    assignment_expression(tokens)
}

///```grammar
/// expression_statement
/// 	: ';'
///    	| expression ';'
/// 	;
/// ```
pub fn expression_statement(tokens: &mut Tokens) -> Result<Expr> {
    let base = tokens.span();
    let expression = expression(tokens)?;

    tokens.eat(Token::Semicolon)?;
    parsed_debug!(tokens, &base, &tokens.span());
    return Ok(Expr::from_exprstmt(
        expression,
        merge_span(&base, &tokens.span()),
    ));
}

///
/// ```grammar
/// statement
/// 	: labeled_statement
/// 	| compound_statement
/// 	| expression_statement
/// 	| selection_statement
/// 	| iteration_statement
/// 	| jump_statement
/// 	;
/// ```
///
pub fn statement(tokens: &mut Tokens) -> Result<Expr> {
    let base = tokens.span();

    if tokens.try_eat(Token::Return) {
        tokens.eat(Token::Semicolon)?;
        return Ok(Expr::from_return(merge_span(&base, &tokens.span())));
    }

    if tokens.try_eat(Token::LeftBrace) {
        let mut stmts = vec![];
        while !tokens.try_eat(Token::RightBrace) {
            stmts.push(statement(tokens)?);
        }
        return Ok(Expr::from_compound(
            stmts,
            merge_span(&base, &tokens.span()),
        ));
    }

    if tokens.try_eat(Token::If) {
        tokens.eat(Token::LeftParen)?;
        let condition = expression(tokens)?;
        tokens.eat(Token::RightParen)?;
        let then_statement = statement(tokens)?;
        let else_statement = if tokens.try_eat(Token::Else) {
            Some(statement(tokens)?)
        } else {
            None
        };
        return Ok(Expr::from_if(
            condition,
            then_statement,
            else_statement,
            merge_span(&base, &tokens.span()),
        ));
    }

    return expression_statement(tokens);
}

fn program_expression(tokens: &mut Tokens) -> Result<Expr> {
    let mut program_types = vec![];
    let base = tokens.span();

    match tokens.read() {
        Token::Kprobe => {
            tokens.eat(Token::Colon).unwrap();
            let ident = tokens.eat_identifier().unwrap();
            program_types.push(Expr::new_type(
                Type::kprobe(ident),
                merge_span(&base, &tokens.span()),
            ));
        }
        Token::Kretprobe => {
            tokens.eat(Token::Colon).unwrap();
            let ident = tokens.eat_identifier().unwrap();
            program_types.push(Expr::new_type(
                Type::kretprobe(ident),
                merge_span(&base, &tokens.span()),
            ));
        }
        _ => {
            bail!("Please specify bpf program type, such as begin, end, k(ret)probe or tracepoint")
        }
    }

    loop {
        if tokens.peek() == Token::LeftBrace {
            return Ok(Expr::from_trace(
                program_types,
                statement(tokens)?,
                merge_span(&base, &tokens.span()),
            ));
        }

        match tokens.read() {
            _ => {
                bail!("begin or end bpf program type is single")
            }
        }
    }
}

fn generate_ast(tokens: &mut Tokens) -> Result<Ast> {
    let mut expressions = vec![];

    loop {
        if tokens.is_eof() {
            return Ok(Ast { exprs: expressions });
        }
        expressions.push(program_expression(tokens)?);
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Ast {
    pub exprs: Vec<Expr>,
}

impl<'text> From<&mut Tokens<'text>> for Ast {
    fn from(tokens: &mut Tokens) -> Self {
        match generate_ast(tokens) {
            Ok(ast) => {
                return ast;
            }
            Err(e) => {
                log::error!(
                    "Failed to parse, left string: {}, error: {}",
                    tokens.left_str(),
                    e
                );
                panic!();
            }
        }
    }
}

impl From<&str> for Ast {
    fn from(source: &str) -> Self {
        let mut tokens = Tokens::from(source);
        Ast::from(&mut tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_statement() {
        let _ = Ast::from("kprobe:tcp_sendmsg {  }");
        let _ = Ast::from("kprobe:tcp_sendmsg { a = 0; }");
        let _ = Ast::from("kprobe:tcp_sendmsg { a = 0; if (a == 0) { a = 2; } }");
        let _ = Ast::from("kprobe:tcp_sendmsg { a = 0; if (a == 0) { a = 2; } else { a = 3; } }");
    }

    #[test]
    fn map_operation() {
        let _ = Ast::from("kprobe:tcp_sendmsg { a[2] = 0; }");
        let _ = Ast::from("kprobe:tcp_sendmsg { print(a[2]); }");
        let _ = Ast::from("kprobe:tcp_sendmsg { print(a[2 + 3]); }");
    }

    #[test]
    fn member_access() {
        let _ = Ast::from("kprobe:tcp_sendmsg { a = skb.head; }");
        let _ = Ast::from("kprobe:tcp_sendmsg { a = skb->head; }");
    }
}
