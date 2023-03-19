use libfirm_rs::{Mode, Node, Tarval};

// get map node by map fd
pub fn map_node(fd: i64) -> Node {
    let mut map = Node::new_const(&Tarval::new_long(fd, &Mode::ModeLu()));
    map.set_const_mapfd();
    map
}
