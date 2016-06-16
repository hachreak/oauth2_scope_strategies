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
%%% @doc OAuth2 Scope Strategies - Tests.
%%% @end

-module(oauth2_scope_strategies_tests).

-author('Leonardo Rossi <leonardo.rossi@studenti.unipr.it>').

-include_lib("eunit/include/eunit.hrl").

mux_test_() ->
  {setup,
    fun start/0,
    fun stop/1,
    fun (SetupData) ->
        [
         set_subpath(SetupData)
        ]
    end
  }.

start() ->
  ok.

stop(_Pid) ->
  ok.

set_subpath(_) ->
  fun() ->
      ?assertEqual(
         <<"read.users.pippo.boxes">>,
         oauth2_scope_strategies:set_subpath(
           <<"read">>, <<"users.pippo.boxes">>)),
      ?assertEqual(
         <<"read.users.pippo.boxes">>,
         oauth2_scope_strategies:set_subpath(
           <<"read">>, <<"users.pippo">>, <<"boxes">>))
  end.
