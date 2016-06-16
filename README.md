oauth2_scope_strategies
=======================

A compilation of scope strategies to be able to implement a `backend` for
the `oauth2` library.

You can use them to implement the `verify_scope()` callback for the
[oauth2](https://github.com/kivra/oauth2) library.

To find an usage example, look the project
[oauth2_mongopool](https://github.com/hachreak/oauth2_mongopool).

Strategies
----------

* [`oauth2_scope_strategy_simple`] A scope is implemented as a set and loosely
  modeled after the Solaris RBAC priviliges, as done in oauth2 library.

* [`oauth2_scope_strategy_fq`] A scope is implemented as a tuple
  `{action, object_path}`. This permit a more accurate permission check
  because you can separate privileges of `read` and `write`.

Build
-----

    $ rebar3 compile
