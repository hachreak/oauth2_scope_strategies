%%% @author Leonardo Rossi <leonardo.rossi@studenti.unipr.it>
%%% @copyright (C) 2016 Leonardo Rossi
%%%
%%% This software is free software; you can redistribute it and/or
%%% modify it under the terms of the GNU General Public License as
%%% published by the Free Software Foundation; either version 2 of the
%%% License, or (at your option) any later version.
%%%
%%% This software is distributed in the hope that it will be useful, but
%%% WITHOUT ANY WARRANTY; without even the implied warranty of
%%% MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
%%% General Public License for more details.
%%%
%%% You should have received a copy of the GNU General Public License
%%% along with this software; if not, write to the Free Software Foundation,
%%% Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
%%%
%%% @doc Strategy Simple: check if the first scope is a subset of the
%%% second one.
%%% @end

-module(oauth2_scope_strategy_simple).

%% API exports
-export([verify/2, reduce/2]).

%% Types

-type scope() :: oauth2_scope_strategies:scope().

%%====================================================================
%% API functions
%%====================================================================

-spec verify(scope(), scope()) -> boolean().
verify(_Scope1, undefined) -> true;
verify(_Scope1, []) -> true;
verify(RequiredScope, PermittedScope) ->
  oauth2_priv_set:is_subset(
    oauth2_priv_set:new(PermittedScope),
    oauth2_priv_set:new(RequiredScope)).

-spec reduce(scope(), scope()) -> {true, scope()} | false.
reduce(RequiredScope, PermittedScope) ->
  case oauth2_scope_strategy_simple:verify(
         RequiredScope, PermittedScope) of
    true -> {true, RequiredScope};
    false ->
      case oauth2_scope_strategy_simple:verify(
             PermittedScope, RequiredScope) of
        true -> {true, PermittedScope};
        false -> false
      end
  end.
