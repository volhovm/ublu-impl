#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]

use ublu_impl::CC;

fn main() {
    ublu_impl::consistency::check_ublu_lang_consistency::<CC>();
}
