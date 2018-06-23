#!/bin/bash
cp ./target/release/stupid_encoder ./target/release/stupid_encoder_compressed
strip -s ./target/release/stupid_encoder_compressed
upx --best --overlay=strip ./target/release/stupid_encoder_compressed
