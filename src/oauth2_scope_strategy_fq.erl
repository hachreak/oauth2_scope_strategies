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
%%% @doc Strategy Fully Qualified scopes:
%%%
%%% In this case the scope is not simply a binary, but a tuple formed by
%%% a action (read, write, all) and the scope as defined by the oauth2 module.
%%%
%%% The verification involve the check of the action if it's permitted and,
%%% conseguently, also if the scope is a sub-scope of the second one.
%%%
%%% An example of Fully Qualified scope is:
%%%
%%%   <<"read.users.john">>
%%%
%%% It means: a action "read" of the user "john".
%%%
%%% Just an example:
%%%
%%%   The box "fuu" is protected on write by the scope <<"write.boxes.fuu">>.
%%%   If a user have all prossible permission on object like
%%%   <<"all.boxes.fuu">>.
%%%
%%%   The check will be:
%%%
%%%     case verify_scope(
%%%         [{<<"write">>, <<"boxes.fuu">>}], [<<"all.boxes.fuu">>]) of
%%%       true  -> io:print("Write permitted");
%%%       false -> io:print("Permission denied!")
%%%     end.
%%%
%%% NOTE:
%%% You can specify multiple required fully qualified scopes.
%%% In this case, to pass the test, all permitted scopes should be a superset
%%% of required scopes.
%%%
%%% E.g.
%%%    true = verify_scope(
%%%      [{<<"write">>, <<"boxes.1">>}, {<<"write">>, <<"boxes.2">>}],
%%%      [{<<"write">>, <<"boxes.1">>}, {<<"write">>, <<"boxes.2">>},
%%%       {<<"write">>, <<"boxes.3">>}]).
%%%
%%% or:
%%%    true = verify_scope(
%%%      [{<<"write">>, <<"boxes.1">>}, {<<"write">>, <<"boxes.2">>}],
%%%      [{<<"write">>, <<"boxes">>}]).
%%%
%%% @end

-module(oauth2_scope_strategy_fq).

%% API exports
-export([verify_scope/2, reduce/2]).

%% API
-export([explode/1, implode/1, build/2]).

-ifdef(TEST).
-compile(export_all).
-endif.

%% Types

-export_type([action/0, fqscope/0, fqscopes/0]).

-type single_scope()  :: oauth2_scope_strategies:single_scope().
-type scope()         :: oauth2:scope().
-type action()        :: binary().
% fully qualified scope (action + scope)
-type fqscope()       :: {action(), single_scope()}.
% list of fully qualified scopes.
-type fqscopes()      :: [fqscope()].

%%====================================================================
%% API functions
%%====================================================================

-spec verify_scope(fqscopes(), fqscopes()) -> boolean().
verify_scope(RequiredFQScopes, PermittedFQScopes) ->
  lists:all(fun(RequiredFQScope) ->
                check_fqscope(RequiredFQScope, PermittedFQScopes)
            end, RequiredFQScopes).

-spec explode(scope()) -> fqscopes().
explode(FQScope) when is_binary(FQScope) ->
  explode([FQScope]);
explode([]) -> [];
explode([FQScope | Rest]) ->
  [Action | [Scope]] = binary:split(FQScope, <<".">>),
  FQScopeExtracted = case is_method(Action) of
    false -> {<<"all">>, FQScope};
    true -> {Action, Scope}
  end,
  [FQScopeExtracted | explode(Rest)].

-spec implode(fqscope() | fqscopes()) -> scope().
implode({Action, Scope}) ->
  oauth2_scope_strategies:set_subpath(Action, Scope);
implode([]) -> [];
implode([{Action, Scope} | Rest]) ->
  [implode({Action, Scope}) | implode(Rest)].

-spec build(action(), scope()) -> fqscopes().
build(Action, Scope) -> [{Action, Scope}].

-spec reduce(fqscope(), fqscope()) -> {true, fqscope()} | false.
reduce(RequiredFQScope, PermittedFQScope) ->
  try
    {RequiredAction, RequiredScope} = RequiredFQScope,
    {PermittedAction, PermittedScope} = PermittedFQScope,
    MinimumAction = minimum_action(RequiredAction, PermittedAction),
    case oauth2_scope_strategy_simple:reduce(
                     RequiredScope, PermittedScope) of
      false -> false;
      {true, MinimumScope} -> {true, {MinimumAction, MinimumScope}}
    end
  catch
    incompatible_actions -> false
  end.

%% Private functions

-spec minimum_action(action(), action()) -> action() | no_return().
minimum_action(<<"all">>, Action) -> Action;
minimum_action(Action, <<"all">>) -> Action;
minimum_action(Action, Action) -> Action;
minimum_action(_, _) -> throw(incompatible_actions).

-spec check_fqscope(fqscope(), fqscopes()) -> boolean().
check_fqscope({RequiredAction, RequiredScope}, PermittedFQScopes) ->
  lists:any(fun({PermittedAction, PermittedScope}) ->
      action_is_permitted(PermittedAction, RequiredAction)
      and
      oauth2_scope_strategy_simple:verify_scope(RequiredScope, PermittedScope)
    end, PermittedFQScopes).

-spec action_is_permitted(action(), action()) -> boolean().
action_is_permitted(Action, Action) -> true;
action_is_permitted(<<"all">>, _RequiredAction) -> true;
action_is_permitted(_PermittedAction, _RequiredAction) -> false.

-spec is_method(binary()) -> boolean().
is_method(<<"read">>) -> true;
is_method(<<"write">>) -> true;
is_method(<<"all">>) -> true;
is_method(_Rest)-> false.
