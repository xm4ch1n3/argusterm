use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::Frame;

pub const FLAME_W: u16 = 7;
pub const FLAME_TOP_H: u16 = 4;

pub const SUBTITLE: &str =
    "And the goddess stirred in him unwearying strength: \
     sleep never fell upon his eyes; but he kept sure watch always.";

// NOTE: XorShift64 — fast non-crypto PRNG, no external dep
fn xorshift(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

pub struct FlameGrid {
    pub grid: Vec<u8>,
    pub width: usize,
    pub height: usize,
    seed: u64,
}

impl FlameGrid {
    pub fn new(seed: u64) -> Self {
        Self { grid: Vec::new(), width: 0, height: 0, seed }
    }

    pub fn resize(&mut self, w: usize, h: usize) {
        if self.width == w && self.height == h {
            return;
        }
        self.width = w;
        self.height = h;
        self.grid.resize(w * h, 0);
    }

    fn inject(&mut self, idx: usize, r: u64) {
        self.grid[idx] = match r % 5 {
            0 => (r % 80 + 175) as u8,
            1 => (r % 60 + 80) as u8,
            _ => (r % 30) as u8,
        };
    }

    // heat source at x = w-1 (TUI border), spreads leftward
    pub fn tick_left(&mut self) {
        if self.grid.is_empty() {
            return;
        }
        let (w, h) = (self.width, self.height);
        for y in 0..h {
            let r = xorshift(&mut self.seed);
            self.inject(y * w + w - 1, r);
        }
        for y in 0..h {
            for x in 0..w - 1 {
                let ri = y * w + x + 1;
                let above = if y > 0 { self.grid[ri - w] } else { 0 } as u16;
                let below = if y + 1 < h { self.grid[ri + w] } else { 0 } as u16;
                self.grid[y * w + x] =
                    ((self.grid[ri] as u16 * 2 + above + below) / 4).saturating_sub(10) as u8;
            }
        }
    }

    // heat source at x = 0 (TUI border), spreads rightward
    pub fn tick_right(&mut self) {
        if self.grid.is_empty() {
            return;
        }
        let (w, h) = (self.width, self.height);
        for y in 0..h {
            let r = xorshift(&mut self.seed);
            self.inject(y * w, r);
        }
        for y in 0..h {
            for x in (1..w).rev() {
                let li = y * w + x - 1;
                let above = if y > 0 { self.grid[li - w] } else { 0 } as u16;
                let below = if y + 1 < h { self.grid[li + w] } else { 0 } as u16;
                self.grid[y * w + x] =
                    ((self.grid[li] as u16 * 2 + above + below) / 4).saturating_sub(10) as u8;
            }
        }
    }

    // heat source at y = h-1 (TUI border), spreads upward
    pub fn tick_top(&mut self) {
        if self.grid.is_empty() {
            return;
        }
        let (w, h) = (self.width, self.height);
        for x in 0..w {
            let r = xorshift(&mut self.seed);
            self.inject((h - 1) * w + x, r);
        }
        // NOTE: iterate top-down so each cell reads from row below (not yet updated this tick)
        for y in 0..h - 1 {
            for x in 0..w {
                let bi = (y + 1) * w + x;
                let left = if x > 0 { self.grid[bi - 1] } else { 0 } as u16;
                let right = if x + 1 < w { self.grid[bi + 1] } else { 0 } as u16;
                self.grid[y * w + x] =
                    ((self.grid[bi] as u16 * 2 + left + right) / 4).saturating_sub(10) as u8;
            }
        }
    }
}

// NOTE: heat → (char, foreground color); char gives texture, color gives intensity
fn heat_glyph(heat: u8) -> (char, Color) {
    match heat {
        0..=20 => (' ', Color::Black),
        21..=60 => ('░', Color::Rgb(120, 0, 0)),
        61..=100 => ('▒', Color::Rgb(200, 50, 0)),
        101..=140 => ('▓', Color::Rgb(255, 130, 0)),
        141..=180 => ('█', Color::Rgb(255, 210, 0)),
        181..=220 => ('█', Color::Yellow),
        _ => ('█', Color::White),
    }
}

pub fn render_flames(frame: &mut Frame, area: Rect, flame: &FlameGrid) {
    if area.width == 0 || area.height == 0 || flame.grid.is_empty() {
        return;
    }
    let buf = frame.buffer_mut();
    for row in 0..area.height as usize {
        let fy = row.min(flame.height.saturating_sub(1));
        for col in 0..area.width as usize {
            let fx = col.min(flame.width.saturating_sub(1));
            let (ch, fg) = heat_glyph(flame.grid[fy * flame.width + fx]);
            if let Some(cell) = buf.cell_mut((area.x + col as u16, area.y + row as u16)) {
                cell.set_char(ch);
                cell.fg = fg;
                cell.bg = Color::Black;
            }
        }
    }
}

