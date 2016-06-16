-module(oauth2_scope_strategies).

%% API exports
-export([set_subpath/2, set_subpath/3]).

-type single_scope()  :: binary().

%%====================================================================
%% API functions
%%====================================================================

-spec set_subpath(single_scope(), single_scope()) -> single_scope().
set_subpath(BaseScope, ExtendedScope) ->
  << BaseScope/binary, <<".">>/binary, ExtendedScope/binary >>.

-spec set_subpath(single_scope(), single_scope(), single_scope()) ->
    single_scope().
set_subpath(BaseScope, FirstLevel, SecondLevel) ->
  set_subpath(set_subpath(BaseScope, FirstLevel), SecondLevel).

%%====================================================================
%% Internal functions
%%====================================================================
