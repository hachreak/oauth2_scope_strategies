%%% @author Leonardo Rossi <leonardo.rossi@studenti.unipr.it>
%%% @copyright (C) 2015, 2016 Leonardo Rossi
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
%%% @doc OAuth2 Scope Strategy FQ - Tests.
%%% @end

-module(oauth2_scope_strategy_fq_tests).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-include_lib("eunit/include/eunit.hrl").

mux_test_() ->
  {setup,
    fun start/0,
    fun stop/1,
    fun (SetupData) ->
        [
         verify_scope_test(SetupData),
         action_is_permitted(SetupData),
         explode(SetupData),
         is_method(SetupData),
         implode(SetupData)
        ]
    end
  }.

start() ->
  ok.

stop(_Pid) ->
  ok.

verify_scope_test(_SetupData) ->
  fun() ->
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test">>}],
        % but I can access only to
        [<<"read.users.test.boxes">>],
        % result
        false),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes.fuu">>}],
        % but I can access only to
        [<<"read.users.test.boxes">>],
        % result
        true),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes">>}],
        % but I can access only to
        [<<"read.users.test.boxes">>],
        % result
        true),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes">>}],
        % but I can access only to
        [<<"read.users.test.boxes.1">>],
        % result
        false),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes.1">>},
         {<<"read">>, <<"users.test.boxes.2">>}],
        % but I can access only to
        [<<"read.users.test.boxes.1">>],
        % result
        false),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes.1">>},
         {<<"read">>, <<"users.test.boxes.2">>}],
        % but I can access only to
        [<<"read.users.test.boxes.3">>],
        % result
        false),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes.1">>},
         {<<"read">>, <<"users.test.boxes.2">>}],
        % but I can access only to
        [<<"read.users.test.boxes.3">>,
         <<"read.users.test.boxes.1">>],
        % result
        false),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes.1">>},
         {<<"read">>, <<"users.test.boxes.2">>}],
        % but I can access only to
        [<<"read.users.test.boxes.3">>,
         <<"read.users.test.boxes.2">>,
         <<"read.users.test.boxes.1">>],
        % result
        true),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes.1">>}],
        % but I can access only to
        [<<"write.users.test.boxes.1">>],
        % result
        false),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes.1">>}],
        % but I can access only to
        [<<"all.users.test.boxes.1">>],
        % result
        true),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes.1">>}],
        % but I can access only to
        [<<"users.test.boxes.1">>],
        % result
        true),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes.1">>}],
        % but I can access only to
        [<<"all.users.test.boxes.2">>],
        % result
        false),
      check_scope(
        % I want to access to:
        [{<<"read">>, <<"users.test.boxes.1">>}],
        % but I can access only to
        [<<"users.test.boxes.2">>],
        % result
        false)
  end.

action_is_permitted(_) ->
  fun() ->
    ?assertEqual(
       true,
       oauth2_scope_strategy_fq:action_is_permitted(
         <<"read">>, <<"read">>)),
    ?assertEqual(
       false,
       oauth2_scope_strategy_fq:action_is_permitted(
         <<"read">>, <<"write">>)),
    ?assertEqual(
       false,
       oauth2_scope_strategy_fq:action_is_permitted(
         <<"read">>, <<"all">>)),
    ?assertEqual(
       true,
       oauth2_scope_strategy_fq:action_is_permitted(
         <<"all">>, <<"all">>)),
    ?assertEqual(
       true,
       oauth2_scope_strategy_fq:action_is_permitted(
         <<"all">>, <<"write">>))
  end.

explode(_) ->
  fun() ->
      ?assertEqual(
         [{<<"read">>, <<"users.test_user.boxes.100.data">>}],
         oauth2_scope_strategy_fq:explode(
           <<"read.users.test_user.boxes.100.data">>)),
      ?assertEqual(
         [{<<"write">>, <<"users.pippo.boxes.100.data">>},
          {<<"read">>, <<"users.test_user.boxes.100.data">>},
          {<<"all">>, <<"users.test_user.boxes.100.data">>}],
         oauth2_scope_strategy_fq:explode(
           [<<"write.users.pippo.boxes.100.data">>,
            <<"read.users.test_user.boxes.100.data">>,
            <<"users.test_user.boxes.100.data">>]))
  end.

is_method(_) ->
  fun() ->
    ?assertEqual(true, oauth2_scope_strategy_fq:is_method(<<"read">>)),
    ?assertEqual(true, oauth2_scope_strategy_fq:is_method(<<"write">>)),
    ?assertEqual(false, oauth2_scope_strategy_fq:is_method(<<"other">>))
  end.

implode(_) ->
  fun() ->
      ?assertEqual(
         <<"read.users.pippo.boxes">>,
         oauth2_scope_strategy_fq:implode(
           {<<"read">>, <<"users.pippo.boxes">>})),
      ?assertEqual(
        [<<"read.users.pippo.boxes">>],
        oauth2_scope_strategy_fq:implode(
          [{<<"read">>, <<"users.pippo.boxes">>}])),
      ?assertEqual(
        [<<"read.users.pippo.boxes">>, <<"write.users.pluto">>],
        oauth2_scope_strategy_fq:implode(
          [{<<"read">>, <<"users.pippo.boxes">>},
           {<<"write">>, <<"users.pluto">>}])),
      ?assertEqual([], oauth2_scope_strategy_fq:implode([]))
  end.

%% private functions

check_scope(RequiredScope, PermittedScope, ResultExpected) ->
  ?assertEqual(
     ResultExpected,
     oauth2_scope_strategy_fq:verify_scope(
       RequiredScope,
       oauth2_scope_strategy_fq:explode(PermittedScope))).