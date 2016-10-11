-module(oauth2_scope_strategies).

%% API exports
-export([set_subpath/2, set_subpath/3]).

-export_type([single_scope/0, scope/0]).

-type single_scope()  :: binary().
-type scope() :: list(single_scope()).

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
