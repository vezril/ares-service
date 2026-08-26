"""Constellation transport: findings to Hermes, captures to Apollo.

Never puts raw RF frames on the bus — Hermes carries small JSON findings, Apollo
carries content-addressed capture blobs, and a finding references its capture by
Apollo address only.
"""
