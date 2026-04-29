#include <metal_stdlib>
using namespace metal;
kernel void fill(texture2d<float, access::write> tex [[texture(0)]],
                 uint2 pos [[thread_position_in_grid]]) {
    tex.write(float4(0.259f, 0.259f, 0.259f, 0.259f), pos);
}
