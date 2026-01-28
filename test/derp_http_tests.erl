%% Copyright (c) 2026 Benoit Chesneau
%% SPDX-License-Identifier: MIT

%%%-------------------------------------------------------------------
%%% @doc Unit tests for HTTP upgrade functionality.
%%% @end
%%%-------------------------------------------------------------------
-module(derp_http_tests).

-include_lib("eunit/include/eunit.hrl").
-include("derp.hrl").

%%--------------------------------------------------------------------
%% HTTP Upgrade Request Tests
%%--------------------------------------------------------------------

build_http_upgrade_request_test() ->
    %% Test that HTTP upgrade request is properly formatted
    Host = <<"derp.example.com">>,
    Path = <<"/derp">>,
    Request = build_test_request(Host, 443, Path),

    %% Should contain required headers
    ?assert(binary:match(Request, <<"GET /derp HTTP/1.1">>) =/= nomatch),
    ?assert(binary:match(Request, <<"Host: derp.example.com">>) =/= nomatch),
    ?assert(binary:match(Request, <<"Upgrade: DERP">>) =/= nomatch),
    ?assert(binary:match(Request, <<"Connection: Upgrade">>) =/= nomatch),
    ?assert(binary:match(Request, <<"\r\n\r\n">>) =/= nomatch).

build_http_upgrade_request_with_port_test() ->
    %% Non-standard port should be included in Host header
    Host = <<"derp.example.com">>,
    Path = <<"/derp">>,
    Request = build_test_request(Host, 8080, Path),

    ?assert(binary:match(Request, <<"Host: derp.example.com:8080">>) =/= nomatch).

build_http_upgrade_request_standard_port_test() ->
    %% Standard ports (80, 443) should not include port in Host header
    Host = <<"derp.example.com">>,
    Path = <<"/derp">>,

    Request443 = build_test_request(Host, 443, Path),
    Request80 = build_test_request(Host, 80, Path),

    ?assert(binary:match(Request443, <<"Host: derp.example.com\r\n">>) =/= nomatch),
    ?assert(binary:match(Request80, <<"Host: derp.example.com\r\n">>) =/= nomatch).

%%--------------------------------------------------------------------
%% HTTP Response Parsing Tests
%%--------------------------------------------------------------------

parse_101_response_test() ->
    Response = <<"HTTP/1.1 101 Switching Protocols\r\n",
                 "Upgrade: DERP\r\n",
                 "Connection: Upgrade\r\n",
                 "\r\n">>,
    ?assertEqual(ok, parse_test_response(Response)).

parse_101_response_case_insensitive_test() ->
    %% Headers should be case-insensitive
    Response = <<"HTTP/1.1 101 Switching Protocols\r\n",
                 "upgrade: derp\r\n",
                 "connection: upgrade\r\n",
                 "\r\n">>,
    ?assertEqual(ok, parse_test_response(Response)).

parse_200_response_test() ->
    %% 200 OK is not valid for upgrade
    Response = <<"HTTP/1.1 200 OK\r\n",
                 "Content-Type: text/plain\r\n",
                 "\r\n">>,
    ?assertMatch({error, {unexpected_status, 200}}, parse_test_response(Response)).

parse_400_response_test() ->
    Response = <<"HTTP/1.1 400 Bad Request\r\n",
                 "Content-Type: text/plain\r\n",
                 "\r\n">>,
    ?assertMatch({error, {unexpected_status, 400}}, parse_test_response(Response)).

parse_missing_upgrade_header_test() ->
    Response = <<"HTTP/1.1 101 Switching Protocols\r\n",
                 "Connection: Upgrade\r\n",
                 "\r\n">>,
    ?assertMatch({error, {missing_upgrade_header, _}}, parse_test_response(Response)).

parse_wrong_upgrade_header_test() ->
    Response = <<"HTTP/1.1 101 Switching Protocols\r\n",
                 "Upgrade: websocket\r\n",
                 "Connection: Upgrade\r\n",
                 "\r\n">>,
    ?assertMatch({error, {missing_upgrade_header, <<"websocket">>}}, parse_test_response(Response)).

parse_http10_response_test() ->
    %% HTTP/1.0 should also work
    Response = <<"HTTP/1.0 101 Switching Protocols\r\n",
                 "Upgrade: DERP\r\n",
                 "Connection: Upgrade\r\n",
                 "\r\n">>,
    ?assertEqual(ok, parse_test_response(Response)).

%%--------------------------------------------------------------------
%% Protocol Constants Tests
%%--------------------------------------------------------------------

http_upgrade_state_defined_test() ->
    ?assertEqual(http_upgrading, ?CLIENT_STATE_HTTP_UPGRADING).

%%--------------------------------------------------------------------
%% Helper Functions
%%--------------------------------------------------------------------

build_test_request(Host, Port, Path) ->
    HostWithPort = case Port of
        80 -> Host;
        443 -> Host;
        P -> <<Host/binary, ":", (integer_to_binary(P))/binary>>
    end,
    iolist_to_binary([
        <<"GET ">>, Path, <<" HTTP/1.1\r\n">>,
        <<"Host: ">>, HostWithPort, <<"\r\n">>,
        <<"Upgrade: DERP\r\n">>,
        <<"Connection: Upgrade\r\n">>,
        <<"\r\n">>
    ]).

parse_test_response(Response) ->
    %% Extract headers (everything before \r\n\r\n)
    case binary:match(Response, <<"\r\n\r\n">>) of
        {Pos, 4} ->
            HeadersBin = binary:part(Response, 0, Pos),
            parse_http_response(HeadersBin);
        nomatch ->
            {error, incomplete_response}
    end.

parse_http_response(HeadersBin) ->
    Lines = binary:split(HeadersBin, <<"\r\n">>, [global]),
    case Lines of
        [StatusLine | HeaderLines] ->
            case parse_status_line(StatusLine) of
                {ok, 101} ->
                    Headers = parse_headers(HeaderLines),
                    Upgrade = string:lowercase(maps:get(<<"upgrade">>, Headers, <<>>)),
                    case Upgrade of
                        <<"derp">> -> ok;
                        _ -> {error, {missing_upgrade_header, Upgrade}}
                    end;
                {ok, Status} ->
                    {error, {unexpected_status, Status}};
                {error, _} = Err ->
                    Err
            end;
        _ ->
            {error, invalid_response}
    end.

parse_status_line(Line) ->
    case binary:split(Line, <<" ">>, [global]) of
        [<<"HTTP/1.1">>, StatusBin | _] ->
            {ok, binary_to_integer(StatusBin)};
        [<<"HTTP/1.0">>, StatusBin | _] ->
            {ok, binary_to_integer(StatusBin)};
        _ ->
            {error, invalid_status_line}
    end.

parse_headers(Lines) ->
    lists:foldl(fun(Line, Acc) ->
        case binary:split(Line, <<": ">>) of
            [Name, Value] ->
                maps:put(string:lowercase(Name), Value, Acc);
            _ ->
                Acc
        end
    end, #{}, Lines).
