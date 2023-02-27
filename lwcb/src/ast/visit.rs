use crate::{
    ast::*,
    types::{Constant, Identifier},
};

pub trait Visit {
    fn visit_ast(&mut self, ast: &Ast) {
        visit_ast(self, ast)
    }

    fn visit_translation_unit(&mut self, unit: &TranslationUnit) {
        visit_translation_unit(self, unit)
    }

    fn visit_bpf_program(&mut self, program: &BpfProgram) {
        visit_bpf_program(self, program)
    }

    fn visit_bpf_program_type(&mut self, program_type: &BpfProgramType) {
        visit_bpf_program_type(self, program_type)
    }

    fn visit_statement(&mut self, statement: &Statement) {
        visit_statement(self, statement)
    }

    fn visit_expression_statement(&mut self, statement: &ExpressionStatement) {
        visit_expression_statement(self, statement)
    }

    fn visit_compound_statement(&mut self, compund_statement: &CompoundStatement) {
        visit_compound_statement(self, compund_statement)
    }

    fn visit_if_statement(&mut self, if_statement: &IfStatement) {
        visit_if_statement(self, if_statement)
    }

    fn visit_return(&mut self) {
        visit_return(self)
    }

    // visit binary expression
    fn visit_binary_expression(&mut self, binary_expression: &BinaryExpression) {
        visit_binary_expression(self, binary_expression)
    }

    fn visit_binary_op(&mut self, binaryop: &BinaryOp) {
        visit_binary_op(self, binaryop)
    }

    fn visit_identifier(&mut self, identifier: &Identifier) {
        visit_identifier(self, identifier)
    }

    fn visit_constant(&mut self, constant: &Constant) {
        visit_constant(self, constant);
    }

    fn visit_string_literal(&mut self, string: &StringLiteral) {
        visit_string_literal(self, string);
    }

    fn visit_call_expression(&mut self, call_expression: &CallExpression) {
        visit_call_expression(self, call_expression);
    }

    fn visit_member_expression(&mut self, member_expression: &MemberExpression) {
        visit_member_expression(self, member_expression);
    }

    fn visit_expression(&mut self, expression: &Expression) {
        visit_expression(self, expression)
    }
}

pub fn visit_ast<V: Visit + ?Sized>(visitor: &mut V, ast: &Ast) {
    visitor.visit_translation_unit(&ast.translation_unit)
}

pub fn visit_identifier<V: Visit + ?Sized>(visitor: &mut V, identifier: &Identifier) {}
pub fn visit_constant<V: Visit + ?Sized>(visitor: &mut V, constant: &Constant) {}
pub fn visit_string_literal<V: Visit + ?Sized>(visitor: &mut V, string: &StringLiteral) {}

pub fn visit_binary_expression<V: Visit + ?Sized>(
    visitor: &mut V,
    binary_expression: &BinaryExpression,
) {
    visitor.visit_expression(&binary_expression.left);
    visitor.visit_expression(&binary_expression.right);
    visitor.visit_binary_op(&binary_expression.op);
}

pub fn visit_binary_op<V: Visit + ?Sized>(visitor: &mut V, binaryop: &BinaryOp) {}

pub fn visit_call_expression<V: Visit + ?Sized>(visitor: &mut V, call_expression: &CallExpression) {
    // todo: Do we need to visit callee?
    // visitor.visit_expression(&call_expression.callee);
    for argument in &call_expression.arguments {
        visitor.visit_expression(argument);
    }
}

pub fn visit_member_expression<V: Visit + ?Sized>(
    visitor: &mut V,
    member_expression: &MemberExpression,
) {
    visitor.visit_identifier(&member_expression.identifier);
    visitor.visit_expression(&member_expression.expression);
}

pub fn visit_expression<V: Visit + ?Sized>(visitor: &mut V, expression: &Expression) {
    match expression {
        Expression::Identifier(i) => visitor.visit_identifier(i),
        Expression::Constant(c) => visitor.visit_constant(c),
        Expression::StringLiteral(s) => visitor.visit_string_literal(s),
        Expression::Binary(b) => visitor.visit_binary_expression(b),
        Expression::Call(c) => visitor.visit_call_expression(c),
        Expression::Member(m) => visitor.visit_member_expression(m),
        _ => unimplemented!(),
    }
}

pub fn visit_expression_statement<V: Visit + ?Sized>(
    visitor: &mut V,
    statement: &ExpressionStatement,
) {
    if let Some(e) = statement {
        visitor.visit_expression(e);
    }
}

pub fn visit_statement<V: Visit + ?Sized>(visitor: &mut V, statement: &Statement) {
    match statement {
        Statement::Compound(c) => visitor.visit_compound_statement(c),
        Statement::Expression(e) => visitor.visit_expression_statement(e),
        Statement::If(i) => visitor.visit_if_statement(i),
        Statement::Return => visitor.visit_return(),
        _ => unimplemented!(),
    }
}

pub fn visit_compound_statement<V: Visit + ?Sized>(
    visitor: &mut V,
    compund_statement: &CompoundStatement,
) {
    for statement in &compund_statement.statements {
        visitor.visit_statement(statement);
    }
}

pub fn visit_bpf_program_type<V: Visit + ?Sized>(visitor: &mut V, program_type: &BpfProgramType) {}

pub fn visit_bpf_program<V: Visit + ?Sized>(visitor: &mut V, program: &BpfProgram) {
    for ty in &program.types {
        visitor.visit_bpf_program_type(ty);
    }
    visitor.visit_statement(&program.statement);
}

pub fn visit_translation_unit<V: Visit + ?Sized>(visitor: &mut V, unit: &TranslationUnit) {
    for program in &unit.programs {
        visitor.visit_bpf_program(program);
    }
}

pub fn visit_if_statement<V: Visit + ?Sized>(visitor: &mut V, if_statement: &IfStatement) {}

pub fn visit_return<V: Visit + ?Sized>(visitor: &mut V) {}
