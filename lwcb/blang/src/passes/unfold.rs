use crate::btf::BTF;
use crate::lexer::Tokens;
use crate::parser::statement;
use crate::parser::Ast;
use crate::parser::Expr;
use crate::parser::ExprKind;
use anyhow::bail;
use anyhow::Result;
use bpfir::types::TypeKind;

fn parse_stmts(stmts: &Vec<String>) -> Result<Vec<Expr>> {
    let mut res = vec![];
    for stmt in stmts {
        let mut tokens = Tokens::from(stmt.as_str());
        res.push(statement(&mut tokens)?);
    }
    Ok(res)
}

pub fn unfold(btf: &BTF, ast: &mut Ast) {
    for expr in &mut ast.exprs {
        unfold_tracing_args(btf, expr).unwrap();
    }
}

struct Unfold {}

impl Unfold {}

fn unfold_tracing_args(btf: &BTF, expr: &mut Expr) -> Result<()> {
    if let Expr {
        kind: ExprKind::Trace(t, b),
        ..
    } = expr
    {
        let mut stmts = vec![];
        if let Expr {
            kind: ExprKind::Type(ty),
            ..
        } = t.as_ref()
        {
            match &ty.kind {
                TypeKind::Kprobe(name) => {
                    let reg_name = vec!["di", "si", "dx", "cx", "r8", "sp"];
                    for (i, (j, z)) in btf.func_args(name).iter().enumerate() {
                        stmts.push(format!(
                            "{} = ({})ctx->{};",
                            j,
                            btf.type_string(*z),
                            reg_name[i]
                        ));
                    }
                }

                TypeKind::Kretprobe(name) => {}
                _ => todo!(),
            }
        }

        let mut exprs = parse_stmts(&stmts)?;
        if let Expr {
            kind: ExprKind::Compound(compound),
            ..
        } = b.as_mut()
        {
            exprs.append(compound);
            std::mem::swap(compound, &mut exprs);
            return Ok(());
        }

        bail!("program entry block is not compound statement")
    }
    bail!("program entry is not tracing declaration")
}
