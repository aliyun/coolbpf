use crate::ast::ast::*;
use crate::builtin_function::BuiltinFunction;
use crate::cmacro::try_enum_to_constant;
use crate::token::{Token, Tokens};
use anyhow::{bail, Result};
pub fn generate_ast(tokens: &mut Tokens) -> Result<TranslationUnit> {
    translation_unit(tokens)
}

pub fn translation_unit(tokens: &mut Tokens) -> Result<TranslationUnit> {
    let mut programs = Vec::new();

    loop {
        if tokens.is_eof() {
            return Ok(TranslationUnit { programs });
        }
        programs.push(bpf_program(tokens)?);
    }
}

pub fn bpf_program(tokens: &mut Tokens) -> Result<BpfProgram> {
    let mut program_types = vec![];
    match tokens.read() {
        Token::Begin => {
            program_types.push(BpfProgramType::Begin);
        }
        Token::Kprobe => {
            let mut ident = None;
            tokens.eat(Token::Colon).unwrap();
            if tokens.peek() == Token::LeftParen && tokens.peek_offset(1).is_type_name() {
                tokens.eat(Token::LeftParen)?;
                let tn = type_name(tokens)?;

                if let Token::Identifier(x) = tokens.peek() {
                    ident = Some(x.name);
                    tokens.eat_identifier()?;
                }

                tokens.eat(Token::RightParen).unwrap();
                program_types.push(BpfProgramType::DynKprobe(DynKprobe { tn, ident }))
            } else {
                let ident = tokens.eat_identifier().unwrap();
                program_types.push(BpfProgramType::Kprobe(ident.name));
            }
        }
        Token::Kretprobe => {
            tokens.eat(Token::Colon).unwrap();
            let ident = tokens.eat_identifier().unwrap();
            program_types.push(BpfProgramType::Kretprobe(ident.name))
        }
        _ => {
            bail!("Please specify bpf program type, such as begin, end, k(ret)probe or tracepoint")
        }
    }

    loop {
        if tokens.peek() == Token::LeftBrace {
            return Ok(BpfProgram {
                types: program_types,
                statement: statement(tokens)?,
            });
        }

        match tokens.read() {
            _ => {
                bail!("begin or end bpf program type is single")
            }
        }
    }
}

pub fn type_name(tokens: &mut Tokens) -> Result<TypeName> {
    let mut identifier = None;
    let mut pointer = 0;
    let ty = match tokens.read() {
        Token::Bool => TypeSpecifier::Bool,
        Token::Char => TypeSpecifier::Char,
        Token::I8 => TypeSpecifier::I8,
        Token::U8 => TypeSpecifier::U8,
        Token::I16 => TypeSpecifier::I16,
        Token::U16 => TypeSpecifier::U16,
        Token::I32 => TypeSpecifier::I32,
        Token::U32 => TypeSpecifier::U32,
        Token::I64 => TypeSpecifier::I64,
        Token::U64 => TypeSpecifier::U64,
        Token::Struct => TypeSpecifier::Struct,
        Token::Union => TypeSpecifier::Union,
        _ => unimplemented!(),
    };

    if TypeSpecifier::Struct == ty {
        identifier = Some(tokens.eat_identifier()?);
    }

    while tokens.try_eat(Token::Star) {
        pointer += 1;
    }

    return Ok(TypeName {
        type_specifier: ty,
        pointers: pointer,
        identifier,
    });
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
pub fn postfix_expression(tokens: &mut Tokens) -> Result<Expression> {
    let mut rename_expression = primary_expression(tokens)?;

    // if tokens.try_eat(Token::LeftBracket) {
    // [] operator
    // }

    loop {
        if tokens.try_eat(Token::LeftBracket) {
            let expression = expression(tokens)?;

            tokens.eat(Token::RightBracket)?;

            rename_expression =
                BinaryExpression::new(BinaryOp::Index, rename_expression, expression).into();
            continue;
        }

        // member expression
        if tokens.try_eat(Token::Dot) {
            rename_expression =
                MemberExpression::new(rename_expression, tokens.eat_identifier()?).into();
            continue;
        }

        if tokens.try_eat(Token::Deref) {
            // replace "->" with an unary expression
            rename_expression =
                UnaryExpression::new(UnaryOperator::Indirection, rename_expression).into();
            rename_expression = MemberExpression {
                expression: Box::new(rename_expression),
                identifier: tokens.eat_identifier()?,
            }
            .into();
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
pub fn primary_expression(tokens: &mut Tokens) -> Result<Expression> {
    if tokens.try_eat(Token::LeftParen) {
        let expression = expression(tokens);
        tokens.eat(Token::RightParen)?;
        return expression;
    }

    match tokens.read() {
        Token::Identifier(i) => {
            if let Ok(func) = BuiltinFunction::try_from(&i.name) {
                if tokens.try_eat(Token::LeftParen) {
                    return Ok(Expression::Call(CallExpression {
                        callee: func,
                        arguments: argument_expression_list(tokens)?,
                    }));
                }
            }

            if let Ok(constant) = try_enum_to_constant(&i.name) {
                return Ok(Expression::Constant(constant));
            }

            return Ok(Expression::Identifier(i));
        }
        Token::Constant(c) => Ok(Expression::Constant(c)),
        // Token::
        Token::StringLiteral(s) => Ok(Expression::StringLiteral(s)),
        _ => bail!("wrong params {:?}", tokens),
    }
}

/// ```grammar
/// argument_expression_list
/// 	: assignment_expression
/// 	| argument_expression_list ',' assignment_expression
/// 	;
/// ```
pub fn argument_expression_list(tokens: &mut Tokens) -> Result<Vec<Expression>> {
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
pub fn multiplicative_expression(tokens: &mut Tokens) -> Result<Expression> {
    let mut expression = cast_expression(tokens)?;

    loop {
        if tokens.try_eat(Token::Star) {
            expression =
                BinaryExpression::new(BinaryOp::Mult, expression, cast_expression(tokens)?).into();
        } else if tokens.try_eat(Token::Slash) {
            expression =
                BinaryExpression::new(BinaryOp::Div, expression, cast_expression(tokens)?).into();
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
pub fn additive_expression(tokens: &mut Tokens) -> Result<Expression> {
    let mut expression = multiplicative_expression(tokens)?;
    loop {
        if tokens.try_eat(Token::Plus) {
            expression = BinaryExpression::new(
                BinaryOp::Add,
                expression,
                multiplicative_expression(tokens)?,
            )
            .into();
        } else if tokens.try_eat(Token::Minus) {
            expression = BinaryExpression::new(
                BinaryOp::Sub,
                expression,
                multiplicative_expression(tokens)?,
            )
            .into();
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
pub fn unary_expression(tokens: &mut Tokens) -> Result<Expression> {
    if tokens.try_eat(Token::Plus) {
        return cast_expression(tokens);
    }

    if tokens.try_eat(Token::Minus) {
        return Ok(UnaryExpression::new(UnaryOperator::Minus, cast_expression(tokens)?).into());
    }

    if tokens.try_eat(Token::Star) {
        return Ok(
            UnaryExpression::new(UnaryOperator::Indirection, cast_expression(tokens)?).into(),
        );
    }

    return postfix_expression(tokens);
}

///```grammar
/// cast_expression
///	    : unary_expression
/// 	| '(' type_name ')' cast_expression
/// 	;
/// ```
pub fn cast_expression(tokens: &mut Tokens) -> Result<Expression> {
    if tokens.peek() == Token::LeftParen && tokens.peek_offset(1).is_type_name() {
        tokens.eat(Token::LeftParen)?;
        let mut pointer = 0;
        let mut identifier = None;
        let ty = match tokens.read() {
            Token::Bool => TypeSpecifier::Bool,
            Token::Char => TypeSpecifier::Char,
            Token::I8 => TypeSpecifier::I8,
            Token::U8 => TypeSpecifier::U8,
            Token::I16 => TypeSpecifier::I16,
            Token::U16 => TypeSpecifier::U16,
            Token::I32 => TypeSpecifier::I32,
            Token::U32 => TypeSpecifier::U32,
            Token::I64 => TypeSpecifier::I64,
            Token::U64 => TypeSpecifier::U64,
            Token::Struct => TypeSpecifier::Struct,
            Token::Union => TypeSpecifier::Union,
            _ => unimplemented!(),
        };

        if TypeSpecifier::Struct == ty {
            identifier = Some(tokens.eat_identifier()?);
        }

        while tokens.try_eat(Token::Star) {
            pointer += 1;
        }
        tokens.eat(Token::RightParen)?;

        return Ok(Expression::Cast(CastExpression {
            type_name: TypeName {
                type_specifier: ty,
                pointers: pointer,
                identifier,
            },
            expression: Box::new(cast_expression(tokens)?),
        }));
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
pub fn equality_expression(tokens: &mut Tokens) -> Result<Expression> {
    let expression = relational_expression(tokens)?;

    if tokens.try_eat(Token::TwoEqual) {
        return Ok(BinaryExpression::new(
            BinaryOp::Equal,
            expression,
            relational_expression(tokens)?,
        )
        .into());
    }

    if tokens.try_eat(Token::NotEqual) {
        return Ok(BinaryExpression::new(
            BinaryOp::NonEqual,
            expression,
            relational_expression(tokens)?,
        )
        .into());
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
pub fn relational_expression(tokens: &mut Tokens) -> Result<Expression> {
    let expression = shift_expression(tokens)?;

    if tokens.try_eat(Token::LessThan) {
        return Ok(
            BinaryExpression::new(BinaryOp::LT, expression, shift_expression(tokens)?).into(),
        );
    }

    if tokens.try_eat(Token::GreaterThan) {
        return Ok(
            BinaryExpression::new(BinaryOp::GT, expression, shift_expression(tokens)?).into(),
        );
    }

    if tokens.try_eat(Token::LessThanEqual) {
        return Ok(
            BinaryExpression::new(BinaryOp::LTE, expression, shift_expression(tokens)?).into(),
        );
    }

    if tokens.try_eat(Token::GreaterThanEqual) {
        return Ok(
            BinaryExpression::new(BinaryOp::GTE, expression, shift_expression(tokens)?).into(),
        );
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
pub fn shift_expression(tokens: &mut Tokens) -> Result<Expression> {
    let expression = additive_expression(tokens)?;

    if tokens.try_eat(Token::LShift) {
        return Ok(BinaryExpression::new(
            BinaryOp::LShift,
            expression,
            additive_expression(tokens)?,
        )
        .into());
    }

    if tokens.try_eat(Token::RShift) {
        return Ok(BinaryExpression::new(
            BinaryOp::RShift,
            expression,
            additive_expression(tokens)?,
        )
        .into());
    }
    return Ok(expression);
}

///```grammar
/// assignment_expression
///	    : conditional_expression
///	    | unary_expression assignment_operator assignment_expression
///	    ;
/// ```
pub fn assignment_expression(tokens: &mut Tokens) -> Result<Expression> {
    let expression = equality_expression(tokens)?;

    if tokens.try_eat(Token::Equal) {
        return Ok(BinaryExpression::new(
            BinaryOp::Assign,
            expression,
            assignment_expression(tokens)?,
        )
        .into());
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
pub fn expression(tokens: &mut Tokens) -> Result<Expression> {
    assignment_expression(tokens)
}

///```grammar
/// expression_statement
/// 	: ';'
///    	| expression ';'
/// 	;
/// ```
pub fn expression_statement(tokens: &mut Tokens) -> Result<Statement> {
    let expression = expression(tokens)?;
    tokens.eat(Token::Semicolon)?;
    return Ok(Statement::Expression(Some(expression)));
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
pub fn statement(tokens: &mut Tokens) -> Result<Statement> {
    if tokens.try_eat(Token::Return) {
        tokens.eat(Token::Semicolon)?;
        return Ok(Statement::Return);
    }

    if tokens.try_eat(Token::LeftBrace) {
        let mut compound_statement = CompoundStatement::new();
        while !tokens.try_eat(Token::RightBrace) {
            compound_statement.push_statement(statement(tokens)?);
        }
        return Ok(Statement::Compound(Box::new(compound_statement)));
    }

    if tokens.try_eat(Token::If) {
        tokens.eat(Token::LeftParen)?;
        let condition = expression(tokens)?;
        tokens.eat(Token::RightParen)?;
        let then_statement = statement(tokens)?;
        let mut if_statement = IfStatement::new(condition, then_statement);
        if tokens.try_eat(Token::Else) {
            let else_statement = statement(tokens)?;
            if_statement.set_else_statement(else_statement);
        }
        return Ok(Statement::If(if_statement));
    }

    return expression_statement(tokens);
}
