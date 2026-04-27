//! CFG builder + renderer.
//!
//! Layout & routing: graphviz `dot -Tplain` with node dimensions proportional
//! to actual box content. We parse BOTH node positions AND edge spline points,
//! then rasterise the polylines onto a character canvas.
//!
//! Fallback: BFS layered layout with channel-based routing (no graphviz needed).

use crate::analysis::DisasmLine;
use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::process::{Command, Stdio};

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum BlockKind { Entry, Exit, CondBranch, UncondBranch, Normal }

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id:       usize,
    pub addr:     u64,
    pub end_addr: u64,
    pub insns:    Vec<DisasmLine>,
    pub kind:     BlockKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EdgeKind { True, False, Uncond }

#[derive(Debug, Clone)]
pub struct CfgEdge { pub from: usize, pub to: usize, pub kind: EdgeKind }

#[derive(Debug, Clone)]
pub struct Cfg { pub blocks: Vec<BasicBlock>, pub edges: Vec<CfgEdge>, pub entry: usize }

// ── Canvas ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CellColor {
    Bg,
    BoxEntry, BoxExit, BoxCond, BoxNormal,
    EdgeTrue, EdgeFalse, EdgeUncond,
    ArrTrue, ArrFalse, ArrUncond,
    TxtHdr, TxtAddr, TxtCall, TxtJump, TxtRet, TxtNorm, TxtOp, TxtDim,
}

#[derive(Debug, Clone)]
pub struct CanvasCell { pub ch: char, pub color: CellColor, pub z: u8 }
impl Default for CanvasCell { fn default() -> Self { CanvasCell { ch: ' ', color: CellColor::Bg, z: 0 } } }

pub struct Canvas { pub cells: Vec<Vec<CanvasCell>>, pub width: usize, pub height: usize }

impl Canvas {
    fn new(w: usize, h: usize) -> Self {
        Self { cells: vec![vec![CanvasCell::default(); w]; h], width: w, height: h }
    }
    pub fn put(&mut self, x: i32, y: i32, ch: char, col: CellColor, z: u8) {
        if x < 0 || y < 0 { return; }
        let (xi, yi) = (x as usize, y as usize);
        if xi < self.width && yi < self.height {
            let c = &mut self.cells[yi][xi];
            if z >= c.z { *c = CanvasCell { ch, color: col, z }; }
        }
    }
    fn str(&mut self, x: i32, y: i32, s: &str, col: CellColor, z: u8) {
        for (i, ch) in s.chars().enumerate() { self.put(x + i as i32, y, ch, col, z); }
    }
    fn wire(&mut self, x: i32, y: i32, ch: char, col: CellColor, z: u8) {
        if x < 0 || y < 0 { return; }
        let (xi, yi) = (x as usize, y as usize);
        if xi >= self.width || yi >= self.height { return; }
        let existing = self.cells[yi][xi].ch;
        let merged = wire_merge(existing, ch);
        self.put(x, y, merged, col, z);
    }
    fn hline(&mut self, x1: i32, x2: i32, y: i32, col: CellColor, z: u8) {
        let (lo, hi) = if x1 <= x2 { (x1, x2) } else { (x2, x1) };
        for x in lo..=hi { self.wire(x, y, '─', col, z); }
    }
    fn vline(&mut self, x: i32, y1: i32, y2: i32, col: CellColor, z: u8) {
        let (lo, hi) = if y1 <= y2 { (y1, y2) } else { (y2, y1) };
        for y in lo..=hi { self.wire(x, y, '│', col, z); }
    }
    /// Draw a polyline through a list of (x,y) screen points
    fn polyline(&mut self, pts: &[(i32, i32)], col: CellColor, z: u8) {
        for w in pts.windows(2) {
            let (x1, y1) = w[0];
            let (x2, y2) = w[1];
            if y1 == y2 {
                self.hline(x1, x2, y1, col, z);
                // corners
                if w.len() > 1 {
                    self.wire(x1.min(x2), y1, if x1 < x2 { '└' } else { '┘' }, col, z);
                    self.wire(x1.max(x2), y1, if x1 < x2 { '┐' } else { '┌' }, col, z);
                }
            } else if x1 == x2 {
                self.vline(x1, y1, y2, col, z);
            } else {
                // diagonal — approximate as L-shape (horizontal then vertical)
                self.hline(x1, x2, y1, col, z);
                self.vline(x2, y1, y2, col, z);
                // corner at bend
                let corner = if x1 < x2 {
                    if y2 > y1 { '┐' } else { '┘' }
                } else {
                    if y2 > y1 { '┌' } else { '└' }
                };
                self.wire(x2, y1, corner, col, z);
            }
        }
    }
}

fn wire_merge(a: char, b: char) -> char {
    match (a, b) {
        (' ', x) | (x, ' ') => x,
        (x, y) if x == y    => x,
        ('─','│')|('│','─') => '┼',
        ('└','─')|('─','└') => '┴',
        ('┘','─')|('─','┘') => '┴',
        ('┌','─')|('─','┌') => '┬',
        ('┐','─')|('─','┐') => '┬',
        ('├',_)|(_, '├')    => '┼',
        ('┤',_)|(_, '┤')    => '┼',
        (_, n)               => n,
    }
}

// ── CFG construction ──────────────────────────────────────────────────────────

pub fn build_cfg(insns: &[DisasmLine]) -> Cfg {
    if insns.is_empty() { return Cfg { blocks: vec![], edges: vec![], entry: 0 }; }
    let func_start = insns[0].address;
    let func_end   = insns.last().map(|i| i.address + i.bytes.len() as u64).unwrap_or(func_start + 1);

    let mut leaders = std::collections::BTreeSet::new();
    leaders.insert(func_start);
    for (i, ins) in insns.iter().enumerate() {
        if ins.is_jump || ins.is_ret {
            if let Some(nx) = insns.get(i + 1) { leaders.insert(nx.address); }
            if let Some(t) = parse_target(ins) {
                if t >= func_start && t < func_end { leaders.insert(t); }
            }
        }
    }

    let lv: Vec<u64> = leaders.into_iter().collect();
    let mut blocks: Vec<BasicBlock> = vec![];
    for (li, &ldr) in lv.iter().enumerate() {
        let next = lv.get(li + 1).copied().unwrap_or(u64::MAX);
        let bi: Vec<DisasmLine> = insns.iter().filter(|i| i.address >= ldr && i.address < next).cloned().collect();
        if bi.is_empty() { continue; }
        let last = bi.last().unwrap();
        let end_addr = last.address + last.bytes.len() as u64;
        let kind = if blocks.is_empty()                      { BlockKind::Entry }
            else if last.is_ret                              { BlockKind::Exit  }
            else if last.is_jump && is_cond(&last.mnemonic) { BlockKind::CondBranch }
            else if last.is_jump                             { BlockKind::UncondBranch }
            else                                             { BlockKind::Normal };
        blocks.push(BasicBlock { id: blocks.len(), addr: ldr, end_addr, insns: bi, kind });
    }

    let mut edges = vec![];
    for blk in &blocks {
        let last = match blk.insns.last() { Some(l) => l, None => continue };
        let fall = last.address + last.bytes.len() as u64;
        if last.is_ret { continue; }
        if last.is_jump {
            if let Some(tgt) = parse_target(last) {
                if let Some(to) = blk_id(&blocks, tgt) {
                    edges.push(CfgEdge { from: blk.id, to, kind: if is_cond(&last.mnemonic) { EdgeKind::True } else { EdgeKind::Uncond } });
                }
            }
            if is_cond(&last.mnemonic) {
                if let Some(to) = blk_id(&blocks, fall) {
                    edges.push(CfgEdge { from: blk.id, to, kind: EdgeKind::False });
                }
            }
        } else if let Some(to) = blk_id(&blocks, fall) {
            edges.push(CfgEdge { from: blk.id, to, kind: EdgeKind::Uncond });
        }
    }

    Cfg { entry: 0, blocks, edges }
}

// ── Graphviz layout + routing ─────────────────────────────────────────────────

const BOX_IW: usize = 46;  // inner content width
const BOX_TW: usize = BOX_IW + 2;  // total with border

struct GvLayout {
    /// Per-block: top-left pixel position on canvas
    node_pos:  Vec<(i32, i32)>,
    /// Per-block: (width, height) in canvas cells
    node_size: Vec<(usize, usize)>,
    /// Per-edge: list of (x,y) canvas waypoints
    edge_pts:  Vec<Vec<(i32, i32)>>,
    canvas_w:  usize,
    canvas_h:  usize,
}

/// Build a DOT graph where each node has width/height proportional to box content.
fn graphviz_layout(cfg: &Cfg, box_heights: &[usize]) -> Option<GvLayout> {
    let n = cfg.blocks.len();
    if n == 0 { return None; }

    // Scale: 1 terminal char ≈ 0.14 inches (at 72dpi), 1 line ≈ 0.22 inches
    // We tell graphviz the exact node dimensions so it spaces them properly
    let char_w_in = 0.115_f64;   // width of one terminal character in inches
    let line_h_in = 0.20_f64;   // height of one line in inches

    let node_w_in = BOX_TW as f64 * char_w_in;

    let mut dot = format!(
        "digraph cfg {{\n  rankdir=TB;\n  nodesep={};\n  ranksep={};\n  splines=ortho;\n",
        (BOX_TW as f64 * char_w_in * 0.4).max(0.5),
        (5.0 * line_h_in)
    );

    for b in &cfg.blocks {
        let h_in = box_heights[b.id] as f64 * line_h_in;
        dot.push_str(&format!(
            "  n{} [shape=box width={:.3} height={:.3} fixedsize=true];\n",
            b.id, node_w_in, h_in
        ));
    }

    // Edge direction: True=left, False=right for cond blocks (radare2 convention)
    for (ei, e) in cfg.edges.iter().enumerate() {
        let attr = match e.kind {
            EdgeKind::True   => " [style=bold color=green]",
            EdgeKind::False  => " [color=red]",
            EdgeKind::Uncond => " [color=blue]",
        };
        dot.push_str(&format!("  n{} -> n{}{} [id=e{}];\n", e.from, e.to, attr, ei));
    }
    dot.push_str("}\n");

    // Run dot
    let mut child = Command::new("dot").arg("-Tplain")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().ok()?;
    child.stdin.take()?.write_all(dot.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() { return None; }

    let text = String::from_utf8_lossy(&out.stdout);

    // Parse graph bounding box
    let mut gv_total_h = 1.0_f64;
    let mut gv_scale_x = 1.0_f64; // pixels per inch
    let mut gv_scale_y = 1.0_f64;

    // Parse "graph S W H" line
    for line in text.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() >= 4 && p[0] == "graph" {
            if let (Ok(w), Ok(h)) = (p[2].parse::<f64>(), p[3].parse::<f64>()) {
                // Compute scale: map gv W→canvas cols, gv H→canvas rows
                let _ = w; // we use per-node sizing
                gv_total_h = h;
                // scale: 1 gv-inch = how many terminal chars
                gv_scale_x = 1.0 / char_w_in;
                gv_scale_y = 1.0 / line_h_in;
            }
            break;
        }
    }

    // Convert gv (cx, cy) to canvas (px, py)
    // gv uses bottom-left origin; canvas is top-left
    let to_canvas = |cx: f64, cy: f64| -> (i32, i32) {
        let screen_x = (cx * gv_scale_x) as i32 + 2;
        let screen_y = ((gv_total_h - cy) * gv_scale_y) as i32 + 2;
        (screen_x, screen_y)
    };

    // Parse nodes
    let mut node_cx: Vec<f64> = vec![0.0; n];
    let mut node_cy: Vec<f64> = vec![0.0; n];
    let mut node_gvw: Vec<f64> = vec![0.0; n];
    let mut node_gvh: Vec<f64> = vec![0.0; n];

    for line in text.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() >= 6 && p[0] == "node" {
            if let Some(id_s) = p[1].strip_prefix('n') {
                if let Ok(id) = id_s.parse::<usize>() {
                    if id < n {
                        if let (Ok(cx), Ok(cy), Ok(w), Ok(h)) = (
                            p[2].parse::<f64>(), p[3].parse::<f64>(),
                            p[4].parse::<f64>(), p[5].parse::<f64>()
                        ) {
                            node_cx[id] = cx; node_cy[id] = cy;
                            node_gvw[id] = w;  node_gvh[id] = h;
                        }
                    }
                }
            }
        }
    }

    // Compute top-left pixel of each box
    let mut node_pos:  Vec<(i32, i32)>    = vec![(0,0); n];
    let mut node_size: Vec<(usize, usize)> = vec![(0,0); n];
    for id in 0..n {
        let (sx, sy) = to_canvas(node_cx[id], node_cy[id]);
        let pw = (node_gvw[id] * gv_scale_x) as usize;
        let ph = (node_gvh[id] * gv_scale_y) as usize;
        // sx/sy is center; convert to top-left
        let tl_x = sx - pw as i32 / 2;
        let tl_y = sy - ph as i32 / 2;
        node_pos[id]  = (tl_x, tl_y);
        node_size[id] = (pw.max(BOX_TW), box_heights[id]);
    }

    // Parse edges — spline control points
    // Format: edge from to N x1 y1 x2 y2 ... [label lx ly] style color
    let ne = cfg.edges.len();
    let mut edge_pts: Vec<Vec<(i32, i32)>> = vec![vec![]; ne];

    // Build name→edge index map
    let mut edge_map: BTreeMap<String, usize> = BTreeMap::new();
    for (ei, e) in cfg.edges.iter().enumerate() {
        edge_map.insert(format!("n{}-n{}", e.from, e.to), ei);
    }

    for line in text.lines() {
        let p: Vec<&str> = line.split_whitespace().collect();
        if p.len() < 5 || p[0] != "edge" { continue; }
        let from_name = p[1];
        let to_name   = p[2];
        let key = format!("{}-{}", from_name, to_name);

        let ei = match edge_map.get(&key) { Some(&i) => i, None => continue };

        let n_pts: usize = match p[3].parse() { Ok(v) => v, Err(_) => continue };
        let mut pts: Vec<(i32, i32)> = Vec::with_capacity(n_pts);

        for k in 0..n_pts {
            let xi = 4 + k * 2;
            let yi = xi + 1;
            if yi >= p.len() { break; }
            if let (Ok(gx), Ok(gy)) = (p[xi].parse::<f64>(), p[yi].parse::<f64>()) {
                let (sx, sy) = to_canvas(gx, gy);
                pts.push((sx, sy));
            }
        }

        // Simplify bezier to polyline: take every 3rd control point (endpoint pairs)
        // For cubic bezier: pts = [p0, c1, c2, p3, c4, c5, p6, ...]
        // The actual curve passes through p0, p3, p6 etc.
        // For rendering we just use all points as a polyline — close enough
        if !pts.is_empty() {
            // Deduplicate consecutive identical points
            let mut deduped: Vec<(i32,i32)> = vec![pts[0]];
            for &pt in &pts[1..] {
                if pt != *deduped.last().unwrap() { deduped.push(pt); }
            }
            edge_pts[ei] = deduped;
        }
    }

    // Compute canvas dimensions
    let max_x = node_pos.iter().zip(node_size.iter())
        .map(|(&(x,_), &(w,_))| x + w as i32).max().unwrap_or(80) as usize + 10;
    let max_y = node_pos.iter().zip(node_size.iter())
        .map(|(&(_,y), &(_,h))| y + h as i32).max().unwrap_or(40) as usize + 10;

    Some(GvLayout { node_pos, node_size, edge_pts, canvas_w: max_x, canvas_h: max_y })
}

// ── BFS fallback layout ───────────────────────────────────────────────────────

const H_STRIDE: usize = BOX_TW + 10;
const V_GAP:    usize = 6;

fn bfs_layout(cfg: &Cfg, box_heights: &[usize]) -> GvLayout {
    let n = cfg.blocks.len();
    let mut layer = vec![0usize; n];
    let mut vis   = vec![false; n];
    let mut q     = VecDeque::new();
    if n > 0 { q.push_back(cfg.entry); vis[cfg.entry] = true; }
    while let Some(id) = q.pop_front() {
        let nexts: Vec<usize> = cfg.edges.iter().filter(|e| e.from == id && !vis[e.to]).map(|e| e.to).collect();
        for to in nexts { layer[to] = layer[id] + 1; vis[to] = true; q.push_back(to); }
    }
    let max_l = *layer.iter().max().unwrap_or(&0);
    for i in 0..n { if !vis[i] { layer[i] = max_l + 1; } }
    let n_rows = max_l + 2;

    let mut col_ctr: BTreeMap<usize,usize> = BTreeMap::new();
    let mut grid_pos = vec![(0usize, 0usize); n];
    for id in 0..n {
        let row = layer[id];
        let c   = *col_ctr.entry(row).or_insert(0);
        col_ctr.insert(row, c + 1);
        grid_pos[id] = (c, row);
    }

    let mut row_mh = vec![3usize; n_rows];
    for i in 0..n { if box_heights[i] > row_mh[grid_pos[i].1] { row_mh[grid_pos[i].1] = box_heights[i]; } }

    let mut row_y = vec![4i32; n_rows];
    for r in 1..n_rows { row_y[r] = row_y[r-1] + row_mh[r-1] as i32 + V_GAP as i32; }

    let mut node_pos  = vec![(0i32, 0i32); n];
    let mut node_size = vec![(BOX_TW, 3usize); n];
    for id in 0..n {
        let (col, row) = grid_pos[id];
        node_pos[id]  = (col as i32 * H_STRIDE as i32 + 2, row_y[row]);
        node_size[id] = (BOX_TW, box_heights[id]);
    }

    // Channel-based edge routing (BFS fallback only)
    let ne = cfg.edges.len();
    let mut edge_pts: Vec<Vec<(i32,i32)>> = vec![vec![]; ne];
    let mut fwd_ch: BTreeMap<(usize,usize), i32> = BTreeMap::new();
    let mut back_lanes: BTreeMap<usize, i32> = BTreeMap::new();

    let mut order: Vec<usize> = (0..ne).collect();
    order.sort_by_key(|&ei| match cfg.edges[ei].kind { EdgeKind::Uncond=>0, EdgeKind::False=>1, EdgeKind::True=>2 });

    for &ei in &order {
        let e  = &cfg.edges[ei];
        let (f, t) = (e.from, e.to);
        let fx = node_pos[f].0 + BOX_TW as i32 / 2;
        let fy = node_pos[f].1 + box_heights[f] as i32 - 1;
        let tx = node_pos[t].0 + BOX_TW as i32 / 2;
        let ty = node_pos[t].1;
        let fr = grid_pos[f].1;
        let tr = grid_pos[t].1;

        if tr > fr {
            let row_bot = row_y[fr] + row_mh[fr] as i32;
            let ch_n = fwd_ch.entry((fr, tr)).or_insert(0);
            let ch_y = row_bot + 1 + (*ch_n % (V_GAP as i32 - 2).max(1));
            *ch_n += 1;
            edge_pts[ei] = vec![(fx, fy+1), (fx, ch_y), (tx, ch_y), (tx, ty)];
        } else {
            let max_col = (0..n).filter(|&i| grid_pos[i].1 >= tr && grid_pos[i].1 <= fr).map(|i| grid_pos[i].0).max().unwrap_or(grid_pos[f].0);
            let lane_n = *back_lanes.entry(max_col).or_insert(0);
            back_lanes.insert(max_col, lane_n + 1);
            let bypass_x = max_col as i32 * H_STRIDE as i32 + 2 + BOX_TW as i32 + 3 + lane_n;
            let top_y = node_pos[t].1 - 2 - lane_n;
            edge_pts[ei] = vec![(fx, fy+1), (fx, fy+2), (bypass_x, fy+2), (bypass_x, top_y), (tx, top_y), (tx, ty)];
        }
    }

    let max_x = node_pos.iter().zip(node_size.iter()).map(|(&(x,_),&(w,_))| x + w as i32).max().unwrap_or(80) as usize + 10;
    let max_y = node_pos.iter().zip(node_size.iter()).map(|(&(_,y),&(_,h))| y + h as i32).max().unwrap_or(40) as usize + 10;
    GvLayout { node_pos, node_size, edge_pts, canvas_w: max_x, canvas_h: max_y }
}

// ── Main render ───────────────────────────────────────────────────────────────

pub fn render_cfg(cfg: &Cfg, _w: usize, _h: usize) -> Canvas {
    if cfg.blocks.is_empty() {
        let mut cv = Canvas::new(60, 4);
        cv.str(2, 1, "No basic blocks found.", CellColor::TxtDim, 1);
        return cv;
    }

    let n = cfg.blocks.len();
    // Box heights: top_border(1) + header(1) + sep(1) + insns + bot_border(1) = insns + 3 + 1
    // But we store border in the box, so: 1(top) + 1(hdr) + 1(sep) + insns + 1(bot) = insns+3
    let box_h: Vec<usize> = cfg.blocks.iter().map(|b| b.insns.len() + 3).collect();

    let layout = graphviz_layout(cfg, &box_h)
        .unwrap_or_else(|| bfs_layout(cfg, &box_h));

    let mut cv = Canvas::new(layout.canvas_w, layout.canvas_h);

    // ── PASS 1: edge wires (z=2) ──────────────────────────────────────────────
    let mut order: Vec<usize> = (0..cfg.edges.len()).collect();
    order.sort_by_key(|&ei| match cfg.edges[ei].kind { EdgeKind::Uncond=>0, EdgeKind::False=>1, EdgeKind::True=>2 });

    for &ei in &order {
        let e = &cfg.edges[ei];
        let (ec, ac) = ecolors(&e.kind);
        let pts = &layout.edge_pts[ei];
        if pts.is_empty() { continue; }

        // Draw the polyline
        for w in pts.windows(2) {
            let (x1, y1) = w[0];
            let (x2, y2) = w[1];
            if y1 == y2 {
                cv.hline(x1, x2, y1, ec, 2);
                // corner chars at ends
                let lx = x1.min(x2); let rx = x1.max(x2);
                if x1 < x2 { cv.wire(lx, y1, '└', ec, 2); cv.wire(rx, y1, '┐', ec, 2); }
                else        { cv.wire(lx, y1, '┌', ec, 2); cv.wire(rx, y1, '┘', ec, 2); }
            } else if x1 == x2 {
                cv.vline(x1, y1, y2, ec, 2);
            } else {
                // L-shape: horizontal then vertical
                cv.hline(x1, x2, y1, ec, 2);
                cv.vline(x2, y1, y2, ec, 2);
                let corner = match (x1 < x2, y2 > y1) {
                    (true,  true)  => '┐',
                    (true,  false) => '┘',
                    (false, true)  => '┌',
                    (false, false) => '└',
                };
                cv.wire(x2, y1, corner, ec, 2);
            }
        }

        // Arrow head at entry point of dest block
        let t = e.to;
        let ty = layout.node_pos[t].1;
        let tx = layout.node_pos[t].0 + layout.node_size[t].0 as i32 / 2;
        cv.put(tx, ty, '▼', ac, 4);
    }

    // ── PASS 2: boxes (z=3) ───────────────────────────────────────────────────
    for i in 0..n {
        let blk = &cfg.blocks[i];
        let (bx, by) = layout.node_pos[i];
        let bw = BOX_TW;
        let bh = box_h[i];
        let z  = 3u8;

        let bc = match blk.kind {
            BlockKind::Entry        => CellColor::BoxEntry,
            BlockKind::Exit         => CellColor::BoxExit,
            BlockKind::CondBranch   => CellColor::BoxCond,
            BlockKind::UncondBranch | BlockKind::Normal => CellColor::BoxNormal,
        };

        // Erase interior including borders
        for row in 0..bh as i32 {
            for col in 0..bw as i32 { cv.put(bx+col, by+row, ' ', CellColor::Bg, z); }
        }

        // Top border
        cv.put(bx, by, '╔', bc, z);
        for xi in 1..bw as i32-1 { cv.put(bx+xi, by, '═', bc, z); }
        cv.put(bx+bw as i32-1, by, '╗', bc, z);

        // Side borders
        for row in 1..bh as i32-1 {
            cv.put(bx,              by+row, '║', bc, z);
            cv.put(bx+bw as i32-1, by+row, '║', bc, z);
        }

        // Header separator (row 2)
        cv.put(bx, by+2, '╠', bc, z);
        for xi in 1..bw as i32-1 { cv.put(bx+xi, by+2, '═', bc, z); }
        cv.put(bx+bw as i32-1, by+2, '╣', bc, z);

        // Bottom border
        let bot = by + bh as i32 - 1;
        cv.put(bx, bot, '╚', bc, z);
        for xi in 1..bw as i32-1 { cv.put(bx+xi, bot, '═', bc, z); }
        cv.put(bx+bw as i32-1, bot, '╝', bc, z);

        // Header text (row 1)
        let tag = match blk.kind {
            BlockKind::Entry        => "ENTRY ",
            BlockKind::Exit         => "RET   ",
            BlockKind::CondBranch   => "COND  ",
            BlockKind::UncondBranch => "JMP   ",
            BlockKind::Normal       => "      ",
        };
        let hc = match blk.kind {
            BlockKind::Entry      => CellColor::BoxEntry,
            BlockKind::Exit       => CellColor::BoxExit,
            BlockKind::CondBranch => CellColor::BoxCond,
            _                     => CellColor::TxtHdr,
        };
        cv.str(bx+1, by+1, &pad(&format!("{:#010x}  {}", blk.addr, tag), BOX_IW), hc, z);

        // Instructions (rows 3+)
        for (li, ins) in blk.insns.iter().enumerate() {
            let iy = by + 3 + li as i32;
            let mc = if ins.is_call { CellColor::TxtCall }
                else if ins.is_ret  { CellColor::TxtRet }
                else if ins.is_jump { CellColor::TxtJump }
                else                { CellColor::TxtNorm };
            let addr = format!("{:#010x}", ins.address);
            let mne  = format!("{:<7}", ins.mnemonic);
            let ops_room = BOX_IW.saturating_sub(addr.len() + 1 + mne.len() + 1);
            let ops  = clip(&ins.operands, ops_room);
            cv.str(bx+1, iy, &addr, CellColor::TxtAddr, z);
            cv.str(bx+1 + addr.len() as i32 + 1, iy, &mne, mc, z);
            cv.str(bx+1 + addr.len() as i32 + 1 + mne.len() as i32 + 1, iy, &ops, CellColor::TxtOp, z);
        }
    }

    // ── PASS 3: arrow heads on top (z=5) ──────────────────────────────────────
    for &ei in &order {
        let e  = &cfg.edges[ei];
        let (_, ac) = ecolors(&e.kind);
        let t  = e.to;
        let tx = layout.node_pos[t].0 + layout.node_size[t].0 as i32 / 2;
        let ty = layout.node_pos[t].1;
        cv.put(tx, ty, '▼', ac, 5);
    }

    cv
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn ecolors(k: &EdgeKind) -> (CellColor, CellColor) {
    match k {
        EdgeKind::True   => (CellColor::EdgeTrue,  CellColor::ArrTrue),
        EdgeKind::False  => (CellColor::EdgeFalse, CellColor::ArrFalse),
        EdgeKind::Uncond => (CellColor::EdgeUncond, CellColor::ArrUncond),
    }
}

fn parse_target(ins: &DisasmLine) -> Option<u64> {
    let s = ins.operands.trim();
    if s.contains(' ') || s.contains('[') || s.contains('@') || s.is_empty() { return None; }
    if s.chars().any(|c| c.is_alphabetic() && !"abcdefABCDEF".contains(c)) { return None; }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(h, 16).ok();
    }
    if s.len() >= 2 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return u64::from_str_radix(s, 16).ok();
    }
    None
}

fn blk_id(blocks: &[BasicBlock], addr: u64) -> Option<usize> {
    blocks.iter().find(|b| b.addr == addr).map(|b| b.id)
}

fn is_cond(mne: &str) -> bool {
    matches!(mne,
        "je"|"jne"|"jz"|"jnz"|"jg"|"jge"|"jl"|"jle"|
        "ja"|"jae"|"jb"|"jbe"|"jo"|"jno"|"js"|"jns"|
        "jp"|"jnp"|"jcxz"|"jecxz"|"jrcxz"|
        "beq"|"bne"|"bge"|"bgt"|"ble"|"blt"
    )
}

fn clip(s: &str, max: usize) -> String {
    if max == 0 { return String::new(); }
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max.saturating_sub(1)]) }
}

fn pad(s: &str, width: usize) -> String {
    if s.len() >= width { s[..width].to_string() }
    else { format!("{:<width$}", s) }
}
