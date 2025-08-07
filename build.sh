#!/bin/bash
g++ CyberSentinel.cpp -o CyberSentinel -lpcap -pthread
echo "Build complete. Run with ./CyberSentinel <mode>"
