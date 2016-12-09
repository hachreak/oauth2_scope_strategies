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
%%% @doc OAuth2 Scope Strategy Simple - Tests.
%%% @end

-module(oauth2_scope_strategy_simple_tests).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-include_lib("eunit/include/eunit.hrl").

mux_test_() ->
  {setup,
    fun start/0,
    fun stop/1,
    fun (SetupData) ->
        [
         verify(SetupData),
         reduce(SetupData),
         expand(SetupData)
        ]
    end
  }.

start() ->
  ok.

stop(_Pid) ->
  ok.

verify(_) ->
  fun() ->
      ?assertEqual(
         true,
         oauth2_scope_strategy_simple:verify(
           <<"users.pippo.boxes.1">>, <<"users.pippo.boxes">>)),
      ?assertEqual(
         false,
         oauth2_scope_strategy_simple:verify(
           <<"users.pippo.boxes">>, <<"users.pippo.boxes.1">>)),
      ?assertEqual(
         false,
         oauth2_scope_strategy_simple:verify(
           <<"users.pippo.boxes">>, <<"users.pippo.client">>)),
      ?assertEqual(
         true,
         oauth2_scope_strategy_simple:verify(
           <<"users.pippo.boxes">>, undefined)),
      ?assertEqual(
         true,
         oauth2_scope_strategy_simple:verify(
           <<"users.pippo.boxes">>, []))

  end.

reduce(_) ->
  fun() ->
    ?assertEqual(false, oauth2_scope_strategy_simple:reduce(
        <<"users.pippo.boxes">>,
        <<"users.pippo.clients">>
      )),
    ?assertEqual(
       {true, <<"users.pippo.boxes">>},
       oauth2_scope_strategy_simple:reduce(
         <<"users.pippo.boxes">>,
         <<"users.pippo.boxes">>
        )),
    ?assertEqual(
       {true, <<"users.pippo.boxes.1">>},
       oauth2_scope_strategy_simple:reduce(
         <<"users.pippo.boxes">>,
         <<"users.pippo.boxes.1">>
        )),
    ?assertEqual(
       {true, <<"users.pippo.boxes.1">>},
       oauth2_scope_strategy_simple:reduce(
         <<"users.pippo.boxes.1">>,
         <<"users.pippo.boxes">>
        )),
    ?assertEqual(
       {true, <<"users.pippo.boxes.1">>},
       oauth2_scope_strategy_simple:reduce(
         <<"users.pippo.boxes.1">>,
         <<"users.pippo.boxes">>
        )),
    ?assertEqual(
       {true, <<"users.pippo.boxes.1">>},
       oauth2_scope_strategy_simple:reduce(
         <<"users.pippo.boxes">>,
         <<"users.pippo.boxes.1">>
        )),
    ?assertEqual(
       {true, <<"users.pippo.boxes.1">>},
       oauth2_scope_strategy_simple:reduce(
         <<"users.pippo.boxes">>,
         <<"users.pippo.boxes.1">>
        )),
    ?assertEqual(
       {true, <<"users.pippo.boxes.1">>},
       oauth2_scope_strategy_simple:reduce(
         <<"users.pippo.boxes.1">>,
         <<"users.pippo.boxes">>
        ))
  end.

expand(_) ->
  fun() ->
    Expected = [
      <<"users.pippo.boxes.1">>,
      <<"users.pippo.boxes">>,
      <<"users.pippo">>,
      <<"users">>
    ],
    SingleScope = <<"users.pippo.boxes.1">>,
    ?assertEqual(Expected, oauth2_scope_strategy_simple:expand(SingleScope))
  end.
