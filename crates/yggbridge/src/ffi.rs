use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    pub fn ygg_init(
        private_key_hex: *const c_char,
        peers_json: *const c_char,
        listen_json: *const c_char,
    ) -> usize;

    pub fn ygg_address(handle: usize) -> *mut c_char;
    pub fn ygg_public_key(handle: usize) -> *mut c_char;

    pub fn ygg_dial(
        handle: usize,
        addr: *const c_char,
        port: c_int,
        err_out: *mut c_char,
        err_out_len: c_int,
    ) -> c_int;

    pub fn ygg_listen(handle: usize, port: c_int) -> usize;

    pub fn ygg_accept(
        listener_handle: usize,
        remote_out: *mut c_char,
        remote_out_len: c_int,
    ) -> c_int;

    pub fn ygg_peers_json(handle: usize) -> *mut c_char;

    pub fn ygg_add_peer(handle: usize, uri: *const c_char) -> c_int;
    pub fn ygg_remove_peer(handle: usize, uri: *const c_char) -> c_int;

    pub fn ygg_shutdown(handle: usize);
    pub fn ygg_goroutine_count() -> c_int;
    pub fn ygg_free(ptr: *mut c_char);
}
