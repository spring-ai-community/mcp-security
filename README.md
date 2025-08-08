# MCP Security

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Java Version](https://img.shields.io/badge/Java-17%2B-orange)](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html)

The MCP Security project
provides [Authorization](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization) support for the
Spring implementations of Model Context Protocol, both client and server.

## Table of Contents

- [Overview](#overview)

## Overview

> ⚠️ This repository is a work in progress

This repository aims to provide the tools to support the Authorization part of the MCP spec in Spring projects.
There are building blocks available in Spring Security, but they are not integrated with Spring AI yet, and this project
provides the glue between AI and Security, as well as missing implementations.

In the project, you'll find dedicated tooling for:

1. MCP Servers
1. MCP Clients (TODO)
1. Authorization Servers

Additionally, [samples](https://github.com/spring-ai-community/mcp-security/tree/main/samples) are available to demo
usage of these tools.