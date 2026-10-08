# WebSentinel v1.0 - Project Architecture

## Overview

WebSentinel is an automated web security assessment framework
designed for authorized testing environments.

## Architecture

```text
                    WebSentinel v1.0
                           |
                           v
                       Target URL
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
       Recon            Crawler       Technology Detection
          |                |                |
          +----------------+----------------+
                           |
                           v
                Security Header Analysis
                           |
                           v
                Sensitive Resource Scan
                           |
                           v
                 Input / Parameter Analysis
                           |
                           v
                Security Misconfiguration
                           |
                           v
                     Risk Engine
                     /         \
                    v           v
               Evidence       SQLite
                    \           /
                     \         /
                      v       v
                    HTML Report
                         |
                         v
                     Dashboard
                         |
                         v
                   Scan Details
