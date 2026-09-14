"""LLM applications: what a running model does, rather than what a file contains.

Everything else in modelwarden reads bytes that are already on disk. This area
sends prompts to an endpoint and judges the answers, so its findings are about
behaviour and are reported as rates over repeated samples, never as a single
pass or fail.
"""
