use libfirm_rs::{get_current_block, Node};
use libfirm_sys::{add_immBlock_pred, mature_immBlock, set_cur_block};

pub struct Target {
    block: Option<Node>,
    first: bool,
}

impl Target {
    pub fn new(block: Option<Node>) -> Self {
        Target {
            block,
            first: false,
        }
    }

    pub fn enter(&mut self) -> Option<Node> {
        if self.block.is_some() && !self.first {
            unsafe { mature_immBlock(self.block.unwrap().raw()) };
        }

        unsafe { set_cur_block(self.block.unwrap().raw()) };
        return self.block.clone();
    }

    pub fn add_pred(&mut self, pred: &Node) {
        if self.block.is_none() {
            self.block = Some(Node::new_immblock());
        } else if self.first {
            let jmp = Node::new_r_jmp(&self.block.unwrap());
            self.block = Some(Node::new_immblock());
            self.first = false;
            unsafe {
                add_immBlock_pred(self.block.unwrap().raw(), jmp.raw());
            }
        }

        unsafe {
            add_immBlock_pred(self.block.unwrap().raw(), pred.raw());
        }
    }

    pub fn jump(&mut self, target: &mut Target) {
        if let Some(block) = get_current_block() {
            if target.block.is_none() {
                target.block = Some(block.clone());
                target.first = true;
                return;
            } else if target.first {
                let jmp = Node::new_r_jmp(&target.block.unwrap());
                target.block = Some(Node::new_immblock());
                target.first = false;
                unsafe {
                    add_immBlock_pred(target.block.unwrap().raw(), jmp.raw());
                }
            }

            let jmp = Node::new_r_jmp(&block);
            unsafe {
                add_immBlock_pred(target.block.unwrap().raw(), jmp.raw());
            }
        }
    }
}
