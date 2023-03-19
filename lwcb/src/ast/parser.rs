use crate::builtin::Builtin;
use crate::cmacro::try_enum_to_constant;
use crate::ast::ast::*;
use crate::token::{Token, TokenStream};
use anyhow::{bail, Result};
use logos::Span;

macro_rules! expr {
    ($kind: expr, $span: expr) => {
        Expr::new (
            $kind,
            $span,
        )
    };
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

pub fn generate_ast(tokens: &mut TokenStream) -> Result<Ast> {
    let mut expressions = vec![];

    loop {
        if tokens.is_eof() {
            return Ok(Ast { exprs: expressions });
        }
        expressions.push(program_expression(tokens)?);
    }
}

pub fn program_expression(tokens: &mut TokenStream) -> Result<Expr> {
    let mut program_types = vec![];

    let left = tokens.span();

    match tokens.read() {
        Token::Kprobe => {
            tokens.eat(Token::Colon).unwrap();
            let ident = tokens.eat_identifier().unwrap();
            program_types.push(Ty::new(TyKind::Kprobe(ident.name), tokens.span()));
        }
        Token::Kretprobe => {
            tokens.eat(Token::Colon).unwrap();
            let ident = tokens.eat_identifier().unwrap();
            program_types.push(Ty::new(TyKind::Kretprobe(ident.name), tokens.span()));
        }
        _ => {
            bail!("Please specify bpf program type, such as begin, end, k(ret)probe or tracepoint")
        }
    }

    let right = tokens.span();

    parsed_debug!(tokens, &left, &right);

    loop {
        if tokens.peek() == Token::LeftBrace {
            let expression = Box::new(statement(tokens)?);
            return Ok(expr!(
                ExprKind::Program(program_types, expression),
                tokens.span()
            ));
        }

        match tokens.read() {
            _ => {
                bail!("begin or end bpf program type is single")
            }
        }
    }
}

fn ty(tokens: &mut TokenStream) -> Result<Ty> {
    let mut type_kind = match tokens.read() {
        Token::Bool => TyKind::Bool,
        Token::Char => TyKind::Char,
        Token::I8 => TyKind::I8,
        Token::U8 => TyKind::U8,
        Token::I16 => TyKind::I16,
        Token::U16 => TyKind::U16,
        Token::I32 => TyKind::I32,
        Token::U32 => TyKind::U32,
        Token::I64 => TyKind::I64,
        Token::U64 => TyKind::U64,
        Token::Struct => TyKind::Struct(tokens.eat_identifier()?.name),
        Token::Union => TyKind::Union(tokens.eat_identifier()?.name),
        _ => todo!(),
    };

    while tokens.try_eat(Token::Star) {
        type_kind = TyKind::Ptr(Box::new(Ty::new(type_kind, tokens.span())));
    }

    tokens.eat(Token::RightParen)?;

    return Ok(Ty::new(type_kind, tokens.span()));
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
pub fn postfix_expression(tokens: &mut TokenStream) -> Result<Expr> {
    let mut rename_expression = primary_expression(tokens)?;

    // if tokens.try_eat(Token::LeftBracket) {
    // [] operator
    // }

    loop {
        if tokens.try_eat(Token::LeftBracket) {
            let expression = expression(tokens)?;

            tokens.eat(Token::RightBracket)?;

            rename_expression = Expr::new_binary(
                BinaryOp::Index,
                rename_expression,
                expression,
                tokens.span(),
            );
            continue;
        }

        // member expression
        if tokens.try_eat(Token::Dot) {
            rename_expression = Expr::new_member(
                rename_expression,
                Expr::new_ident(tokens.eat_identifier()?.name, tokens.span()),
                tokens.span(),
            );
            continue;
        }

        if tokens.try_eat(Token::Deref) {
            // replace "->" with an unary expression
            rename_expression = Expr::new_unary(UnaryOp::Deref, rename_expression, tokens.span());
            rename_expression = Expr::new_member(
                rename_expression,
                Expr::new_ident(tokens.eat_identifier()?.name, tokens.span()),
                tokens.span(),
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
pub fn primary_expression(tokens: &mut TokenStream) -> Result<Expr> {
    if tokens.try_eat(Token::LeftParen) {
        let expression = expression(tokens);
        tokens.eat(Token::RightParen)?;
        return expression;
    }

    match tokens.read() {
        Token::Identifier(i) => {
            if let Ok(func) = Builtin::try_from(i.name.as_str()) {
                if tokens.try_eat(Token::LeftParen) {
                    return Ok(Expr::new_builtincall(
                        func,
                        argument_expression_list(tokens)?,
                        tokens.span(),
                    ));
                }
            }

            if let Ok(constant) = try_enum_to_constant(&i.name) {
                return Ok(Expr::new_const(constant, tokens.span()));
            }

            return Ok(Expr::new_ident(i.name.clone(), tokens.span()));
        }
        Token::Constant(c) => Ok(Expr::new_const(c, tokens.span())),
        // Token::
        Token::StringLiteral(s) => Ok(Expr::new_litstr(s, tokens.span())),
        _ => bail!("wrong params {:?}", tokens),
    }
}

/// ```grammar
/// argument_expression_list
/// 	: assignment_expression
/// 	| argument_expression_list ',' assignment_expression
/// 	;
/// ```
pub fn argument_expression_list(tokens: &mut TokenStream) -> Result<Vec<Expr>> {
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
pub fn multiplicative_expression(tokens: &mut TokenStream) -> Result<Expr> {
    let mut expression = cast_expression(tokens)?;

    loop {
        if tokens.try_eat(Token::Star) {
            expression = Expr::new_binary(
                BinaryOp::Mult,
                expression,
                cast_expression(tokens)?,
                tokens.span(),
            );
        } else if tokens.try_eat(Token::Slash) {
            expression = Expr::new_binary(
                BinaryOp::Div,
                expression,
                cast_expression(tokens)?,
                tokens.span(),
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
pub fn additive_expression(tokens: &mut TokenStream) -> Result<Expr> {
    let mut expression = multiplicative_expression(tokens)?;
    loop {
        if tokens.try_eat(Token::Plus) {
            expression = Expr::new_binary(
                BinaryOp::Add,
                expression,
                multiplicative_expression(tokens)?,
                tokens.span(),
            );
        } else if tokens.try_eat(Token::Minus) {
            expression = Expr::new_binary(
                BinaryOp::Sub,
                expression,
                multiplicative_expression(tokens)?,
                tokens.span(),
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
pub fn unary_expression(tokens: &mut TokenStream) -> Result<Expr> {
    if tokens.try_eat(Token::Plus) {
        return cast_expression(tokens);
    }

    if tokens.try_eat(Token::Minus) {
        return Ok(Expr::new_unary(
            UnaryOp::Neg,
            cast_expression(tokens)?,
            tokens.span(),
        ));
    }

    if tokens.try_eat(Token::Star) {
        return Ok(Expr::new_unary(
            UnaryOp::Deref,
            cast_expression(tokens)?,
            tokens.span(),
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
pub fn cast_expression(tokens: &mut TokenStream) -> Result<Expr> {
    if tokens.peek() == Token::LeftParen && tokens.peek_offset(1).is_type_name() {
        tokens.eat(Token::LeftParen)?;
        let ty = ty(tokens)?;

        return Ok(expr!(
            ExprKind::Cast(Box::new(cast_expression(tokens)?), ty),
            tokens.span()
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
pub fn equality_expression(tokens: &mut TokenStream) -> Result<Expr> {
    let expression = relational_expression(tokens)?;

    if tokens.try_eat(Token::TwoEqual) {
        return Ok(Expr::new_binary(
            BinaryOp::Equal,
            expression,
            relational_expression(tokens)?,
            tokens.span(),
        ));
    }

    if tokens.try_eat(Token::NotEqual) {
        return Ok(Expr::new_binary(
            BinaryOp::NonEqual,
            expression,
            relational_expression(tokens)?,
            tokens.span(),
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
pub fn relational_expression(tokens: &mut TokenStream) -> Result<Expr> {
    let expression = shift_expression(tokens)?;

    if tokens.try_eat(Token::LessThan) {
        return Ok(Expr::new_binary(
            BinaryOp::LT,
            expression,
            shift_expression(tokens)?,
            tokens.span(),
        ));
    }

    if tokens.try_eat(Token::GreaterThan) {
        return Ok(Expr::new_binary(
            BinaryOp::GT,
            expression,
            shift_expression(tokens)?,
            tokens.span(),
        ));
    }

    if tokens.try_eat(Token::LessThanEqual) {
        return Ok(Expr::new_binary(
            BinaryOp::LTE,
            expression,
            shift_expression(tokens)?,
            tokens.span(),
        ));
    }

    if tokens.try_eat(Token::GreaterThanEqual) {
        return Ok(Expr::new_binary(
            BinaryOp::GTE,
            expression,
            shift_expression(tokens)?,
            tokens.span(),
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
pub fn shift_expression(tokens: &mut TokenStream) -> Result<Expr> {
    let expression = additive_expression(tokens)?;

    if tokens.try_eat(Token::LShift) {
        return Ok(expr!(
            ExprKind::Binary(
                BinaryOp::LShift,
                Box::new(expression),
                Box::new(additive_expression(tokens)?)
            ),
            tokens.span()
        ));
    }

    if tokens.try_eat(Token::RShift) {
        return Ok(expr!(
            ExprKind::Binary(
                BinaryOp::RShift,
                Box::new(expression),
                Box::new(additive_expression(tokens)?)
            ),
            tokens.span()
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
pub fn assignment_expression(tokens: &mut TokenStream) -> Result<Expr> {
    let expression = equality_expression(tokens)?;

    if tokens.try_eat(Token::Equal) {
        return Ok(expr!(
            ExprKind::Binary(
                BinaryOp::Assign,
                Box::new(expression),
                Box::new(assignment_expression(tokens)?)
            ),
            tokens.span()
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
pub fn expression(tokens: &mut TokenStream) -> Result<Expr> {
    assignment_expression(tokens)
}

///```grammar
/// expression_statement
/// 	: ';'
///    	| expression ';'
/// 	;
/// ```
pub fn expression_statement(tokens: &mut TokenStream) -> Result<Expr> {
    let left = tokens.span();
    let expression = Box::new(expression(tokens)?);
    let right = tokens.span();
    tokens.eat(Token::Semicolon)?;
    parsed_debug!(tokens, &left, &right);
    return Ok(expr!(ExprKind::ExprStmt(expression), tokens.span()));
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
pub fn statement(tokens: &mut TokenStream) -> Result<Expr> {
    if tokens.try_eat(Token::Return) {
        tokens.eat(Token::Semicolon)?;
        return Ok(expr!(ExprKind::Return, tokens.span()));
    }

    if tokens.try_eat(Token::LeftBrace) {
        let mut stmts = vec![];
        while !tokens.try_eat(Token::RightBrace) {
            stmts.push(statement(tokens)?);
        }
        return Ok(expr!(ExprKind::Compound(stmts), tokens.span()));
    }

    if tokens.try_eat(Token::If) {
        tokens.eat(Token::LeftParen)?;
        let condition = Box::new(expression(tokens)?);
        tokens.eat(Token::RightParen)?;
        let then_statement = Box::new(statement(tokens)?);
        let else_statement = if tokens.try_eat(Token::Else) {
            Some(Box::new(statement(tokens)?))
        } else {
            None
        };
        return Ok(expr!(
            ExprKind::If(condition, then_statement, else_statement),
            tokens.span()
        ));
    }

    return expression_statement(tokens);
}
