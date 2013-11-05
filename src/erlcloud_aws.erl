-module(erlcloud_aws).

-export([aws_request/5, aws_request/6, aws_request/7, aws_request/8,
         aws_request_xml/5, aws_request_xml/6, aws_request_xml/7, aws_request_xml/8,
         aws_request2/7,
         aws_request_xml2/5, aws_request_xml2/7,
         param_list/2, param_list_r/1, param_list_r/2,
         default_config/0, update_config/1, format_timestamp/1,
         http_headers_body/1,
         sign_v4/5]).

-include("erlcloud.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").

-record(metadata_credentials, 
        {access_key_id :: string(),
         secret_access_key :: string(),
         security_token=undefined :: string(),
         expiration_gregorian_seconds :: integer()
        }).

aws_request_xml(Method, Host, Path, Params, #aws_config{} = Config) ->
    Body = aws_request(Method, Host, Path, Params, Config),
    element(1, xmerl_scan:string(Body)).
aws_request_xml(Method, Host, Path, Params, AccessKeyID, SecretAccessKey) ->
    Body = aws_request(Method, Host, Path, Params, AccessKeyID, SecretAccessKey),
    element(1, xmerl_scan:string(Body)).
aws_request_xml(Method, Protocol, Host, Port, Path, Params, #aws_config{} = Config) ->
    Body = aws_request(Method, Protocol, Host, Port, Path, Params, Config),
    element(1, xmerl_scan:string(Body)).
aws_request_xml(Method, Protocol, Host, Port, Path, Params, AccessKeyID, SecretAccessKey) ->
    Body = aws_request(Method, Protocol, Host, Port, Path, Params, AccessKeyID, SecretAccessKey),
    element(1, xmerl_scan:string(Body)).

aws_request_xml2(Method, Host, Path, Params, #aws_config{} = Config) ->
    aws_request_xml2(Method, undefined, Host, undefined, Path, Params, Config).
aws_request_xml2(Method, Protocol, Host, Port, Path, Params, #aws_config{} = Config) ->
    case aws_request2(Method, Protocol, Host, Port, Path, Params, Config) of
        {ok, Body} ->
            {ok, element(1, xmerl_scan:string(Body))};
        {error, Reason} ->
            {error, Reason}
    end.

aws_request(Method, Host, Path, Params, #aws_config{} = Config) ->
    aws_request(Method, undefined, Host, undefined, Path, Params, Config).
aws_request(Method, Host, Path, Params, AccessKeyID, SecretAccessKey) ->
    aws_request(Method, undefined, Host, undefined, Path, Params, AccessKeyID, SecretAccessKey).
aws_request(Method, Protocol, Host, Port, Path, Params, #aws_config{} = Config) ->
    case aws_request2(Method, Protocol, Host, Port, Path, Params, Config) of
        {ok, Body} ->
            Body;
        {error, Reason} ->
            erlang:error({aws_error, Reason})
    end.
aws_request(Method, Protocol, Host, Port, Path, Params, AccessKeyID, SecretAccessKey) ->
    aws_request(Method, Protocol, Host, Port, Path, Params,
                #aws_config{access_key_id = AccessKeyID, secret_access_key = SecretAccessKey}).

%% aws_request2 returns {ok, Body} or {error, Reason} instead of throwing as aws_request does
%% This is the preferred pattern for new APIs
aws_request2(Method, Protocol, Host, Port, Path, Params, Config) ->
    case update_config(Config) of
        {ok, Config1} ->
            aws_request2_no_update(Method, Protocol, Host, Port, Path, Params, Config1);
        {error, Reason} ->
            {error, Reason}
    end.

aws_request2_no_update(Method, Protocol, Host, Port, Path, Params, #aws_config{} = Config) ->
    Timestamp = format_timestamp(erlang:universaltime()),
    QParams = lists:sort([{"Timestamp", Timestamp},
                          {"SignatureVersion", "2"},
                          {"SignatureMethod", "HmacSHA1"},
                          {"AWSAccessKeyId", Config#aws_config.access_key_id}|Params] ++
                             case Config#aws_config.security_token of
                                 undefined -> [];
                                 Token -> [{"SecurityToken", Token}]
                             end),
    
    QueryToSign = erlcloud_http:make_query_string(QParams),
    RequestToSign = [string:to_upper(atom_to_list(Method)), $\n,
                     string:to_lower(Host), $\n, Path, $\n, QueryToSign],
    Signature = base64:encode(crypto:sha_mac(Config#aws_config.secret_access_key, RequestToSign)),
    
    Query = [QueryToSign, "&Signature=", erlcloud_http:url_encode(Signature)],
    
    case Protocol of
        undefined -> UProtocol = "https://";
        _ -> UProtocol = [Protocol, "://"]
    end,
    
    case Port of
        undefined -> URL = [UProtocol, Host, Path];
        _ -> URL = [UProtocol, Host, $:, port_to_str(Port), Path]
    end,
    
    %% Note: httpc MUST be used with {timeout, timeout()} option
    %%       Many timeout related failures is observed at prod env
    %%       when library is used in 24/7 manner
    Response =
        case Method of
            get ->
                Req = lists:flatten([URL, $?, Query]),
                httpc:request(get, {Req, []}, [{timeout, Config#aws_config.timeout}], []);
            _ ->
                httpc:request(Method,
                              {lists:flatten(URL), [], "application/x-www-form-urlencoded; charset=utf-8",
                               list_to_binary(Query)}, [{timeout, Config#aws_config.timeout}], [])
        end,
    
    http_body(Response).

param_list([], _Key) -> [];
param_list(Values, Key) when is_tuple(Key) ->
    Seq = lists:seq(1, size(Key)),
    lists:flatten(
      [[{lists:append([element(J, Key), ".", integer_to_list(I)]),
         element(J, Value)} || J <- Seq] ||
          {I, Value} <- lists:zip(lists:seq(1, length(Values)), Values)]
     );
param_list([[{_, _}|_]|_] = Values, Key) ->
    lists:flatten(
      [[{lists:flatten([Key, $., integer_to_list(I), $., SubKey]),
         value_to_string(Value)} || {SubKey, Value} <- SValues] ||
          {I, SValues} <- lists:zip(lists:seq(1, length(Values)), Values)]
     );
param_list(Values, Key) ->
    [{lists:flatten([Key, $., integer_to_list(I)]), Value} ||
        {I, Value} <- lists:zip(lists:seq(1, length(Values)), Values)].

%% This is a version of the param_list function above that uses
%% recursion to provide a more consistent construction of parameter lists.
%% The problem with list comprehensions is that they do not compose. Therefore
%% the non recursive version of param_list can not build deep nested parameter
%% lists properly. I am not sure if the _r functions provide a replacement
%% for all the use cases of param_list.. quite frankly I found the interface
%% confusing and inconsistent, since all I had to go with is reverse
%% engineering.
param_list_r(_, [], _, _) ->
    [];
param_list_r(Key, [{SubKey, Value} | Rest], Level, Acc) ->
    NAcc = lists:flatten([Acc,$.,SubKey]),
    param_list_r(NAcc, Value, 0, NAcc) ++
        param_list_r(Key, Rest, Level + 1, Acc);
param_list_r(Key, [Value | Rest], Level, Acc) when is_list(Value) ->
    NAcc = Acc ++ [$. | integer_to_list(Level)],
    param_list_r(NAcc, Value, 0, NAcc) ++
        param_list_r(Key, Rest, Level + 1, Acc);
param_list_r(_, undefined, _, _) ->
    [];
param_list_r(_, Value, _, Acc) ->
    [{Acc, Value}].

%%
%% @doc Builds a possibly nested parameter list recursively. The 
%% values provided to the function can be:
%% - a single string or POD type. 
%% - a list containing either:
%%    - strings or POD types
%%    - a tuple describing a sub key.. {SubKey, Values}, where Values
%%      can once more be a string or POD type or a composite list of values
%%      and so on, and so on.
%% So for example:
%% param_list_r("int", "foo") ->
%%     [{"int","foo"}].
%%
%% param_list_r("int", ["foo", "bar"]) ->
%%     [{"int.0","foo"},{"int.1","bar"}].
%% param_list_r("foo", [{"name", "bar"}, {"name", "baz"}]) ->
%%     [{"foo.0.name","fooname"},{"foo.1.bars", "baz"}].
%% param_list_r("int", [{"foo", [{"bar", "baz"}, {"bang", "pang"}]}]) ->
%%     [{"int.0.foo.0.bar","baz"},{"int.0.foo.1.bang","pang"}].
%%
%% I believe one can build almost anything with this scheme, even things that
%% are likely invalid parameters in the AWS API. For example:
%% param_list_r("foo", [["bar", "baz"]]) ->
%%     [{"foo.0.0","bar"},{"foo.0.1","baz"}]
%% so when recursing levels you probably always want to specify a sub key
%% via a tuple. Unless this is truly what you want. I think this scheme 
%% composes well to increase flexibility for current and future versions of the
%% API - EG
%% param_list_r/1 is provided to facilitate building long lists.. this way
%% it is possible to provide all key value(s) pairs as elements of a single
%% list
param_list_r(KVs) ->
    lists:foldl(
      fun({K, V}, A) ->
              param_list_r(K,V) ++ A
      end,
      [],
      KVs).
param_list_r(Key, Values) ->
    param_list_r(Key, Values, 0, Key).

value_to_string(Integer) when is_integer(Integer) -> integer_to_list(Integer);
value_to_string(Atom) when is_atom(Atom) -> atom_to_list(Atom);
value_to_string(Binary) when is_binary(Binary) -> Binary;
value_to_string(String) when is_list(String) -> String;
value_to_string({{_Yr, _Mo, _Da}, {_Hr, _Min, _Sec}} = Timestamp) -> format_timestamp(Timestamp).

format_timestamp({{Yr, Mo, Da}, {H, M, S}}) ->
    lists:flatten(
      io_lib:format("~4.10.0b-~2.10.0b-~2.10.0bT~2.10.0b:~2.10.0b:~2.10.0bZ",
                    [Yr, Mo, Da, H, M, S])).

default_config() ->
    case get(aws_config) of
        undefined ->
            #aws_config{access_key_id=os:getenv("AWS_ACCESS_KEY_ID"),
                        secret_access_key=os:getenv("AWS_SECRET_ACCESS_KEY")};
        Config ->
            Config
    end.

-spec update_config(aws_config()) -> {ok, aws_config()} | {error, term()}.
update_config(#aws_config{access_key_id = KeyId} = Config)
  when is_list(KeyId) ->
    %% In order to support caching of the aws_config, we could store the expiration_time
    %% and check it here. If it is about to expire (within 5 minutes is what boto uses)
    %% then we should get the new config.
    {ok, Config};
update_config(#aws_config{} = Config) ->
    %% AccessKey is not set. Try to read from role metadata.
    case get_metadata_credentials() of
        {error, Reason} ->
            {error, Reason};
        {ok, Credentials} ->
            {ok, Config#aws_config {
                   access_key_id = Credentials#metadata_credentials.access_key_id,
                   secret_access_key = Credentials#metadata_credentials.secret_access_key,
                   security_token = Credentials#metadata_credentials.security_token}}
    end.

-spec get_metadata_credentials() -> {ok, #metadata_credentials{}} | {error, term()}.
get_metadata_credentials() ->
    %% See if we have cached credentials
    case application:get_env(erlcloud, metadata_credentials) of
        {ok, #metadata_credentials{expiration_gregorian_seconds = Expiration} = Credentials} ->
            Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
            %% Get new credentials if these will expire in less than 5 minutes
            case Expiration - Now < 300 of
                true -> get_credentials_from_metadata();
                false -> {ok, Credentials}
            end;
        undefined ->
            get_credentials_from_metadata()
    end.

timestamp_to_gregorian_seconds(Timestamp) ->
    {ok, [Yr, Mo, Da, H, M, S], []} = io_lib:fread("~d-~d-~dT~d:~d:~dZ", binary_to_list(Timestamp)),
    calendar:datetime_to_gregorian_seconds({{Yr, Mo, Da}, {H, M, S}}).
    
-spec get_credentials_from_metadata() -> {ok, #metadata_credentials{}} | {error, term()}.
get_credentials_from_metadata() ->
    %% TODO this function should retry on errors getting credentials
    %% First get the list of roles
    case http_body(httpc:request("http://169.254.169.254/latest/meta-data/iam/security-credentials/")) of
        {error, Reason} ->
            {error, Reason};
        {ok, Body} ->
            %% Always use the first role
            Role = string:sub_word(Body, 1, $\n),
            case http_body(httpc:request(
                             "http://169.254.169.254/latest/meta-data/iam/security-credentials/" ++ Role)) of
                {error, Reason} ->
                    {error, Reason};
                {ok, Json} ->
                    Creds = jsx:decode(list_to_binary(Json)),
                    Record = #metadata_credentials
                        {access_key_id = binary_to_list(proplists:get_value(<<"AccessKeyId">>, Creds)),
                         secret_access_key = binary_to_list(proplists:get_value(<<"SecretAccessKey">>, Creds)),
                         security_token = binary_to_list(proplists:get_value(<<"Token">>, Creds)),
                         expiration_gregorian_seconds = timestamp_to_gregorian_seconds(
                                                          proplists:get_value(<<"Expiration">>, Creds))},
                    application:set_env(erlcloud, metadata_credentials, Record),
                    {ok, Record}
            end
    end.

port_to_str(Port) when is_integer(Port) ->
    integer_to_list(Port);
port_to_str(Port) when is_list(Port) ->
    Port.

-spec http_body({ok, tuple()} | {error, term()}) -> {ok, string()} | {error, tuple()}.
%% Extract the body and do error handling on the return of a httpc:request call.
http_body(Return) ->
    case http_headers_body(Return) of
        {ok, {_, Body}} ->
            {ok, Body};
        {error, Reason} ->
            {error, Reason}
    end.

-type headers() :: [{string(), string()}].
-spec http_headers_body({ok, tuple()} | {error, term()}) -> {ok, {headers(), string()}} | {error, tuple()}.
%% Extract the headers and body and do error handling on the return of a httpc:request call.
http_headers_body({ok, {{_HTTPVer, OKStatus, _StatusLine}, Headers, Body}}) 
  when OKStatus >= 200, OKStatus =< 299 ->
    {ok, {Headers, Body}};
http_headers_body({ok, {{_HTTPVer, Status, StatusLine}, _Headers, Body}}) ->
    {error, {http_error, Status, StatusLine, Body}};
http_headers_body({error, Reason}) ->
    {error, {socket_error, Reason}}.

%% http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
%% TODO additional parameters - currently only supports what is needed for DynamoDB
-spec sign_v4(aws_config(), headers(), binary(), string(), string()) -> headers().
sign_v4(Config, Headers, Payload, Region, Service) ->
    Date = iso_8601_basic_time(),
    Headers1 = [{"x-amz-date", Date} | Headers],
    Headers2 = case Config#aws_config.security_token of
                   undefined -> Headers1;
                   Token -> [{"x-amz-security-token", Token} | Headers1]
               end,
    {Request, SignedHeaders} = canonical_request("POST", "/", "", Headers2, Payload),
    CredentialScope = credential_scope(Date, Region, Service),
    ToSign = to_sign(Date, CredentialScope, Request),
    SigningKey = signing_key(Config, Date, Region, Service),
    Signature = base16(crypto:hmac(sha256, SigningKey, ToSign)),
    Authorization = authorization(Config, CredentialScope, SignedHeaders, Signature),
    [{"Authorization", lists:flatten(Authorization)} | Headers2].
    
iso_8601_basic_time() ->
    {{Year,Month,Day},{Hour,Min,Sec}} = calendar:now_to_universal_time(os:timestamp()),
    lists:flatten(io_lib:format(
                    "~4.10.0B~2.10.0B~2.10.0BT~2.10.0B~2.10.0B~2.10.0BZ",
                    [Year, Month, Day, Hour, Min, Sec])).

canonical_request(Method, CanonicalURI, CanonicalQueryString, Headers, Payload) ->
    {CanonicalHeaders, SignedHeaders} = canonical_headers(Headers),
    {[Method, $\n,
      CanonicalURI, $\n,
      CanonicalQueryString, $\n,
      CanonicalHeaders, $\n,
      SignedHeaders, $\n,
      hash_encode(Payload)],
     SignedHeaders}.

canonical_headers(Headers) ->
    Normalized = [{string:to_lower(Name), trimall(Value)} || {Name, Value} <- Headers],
    Sorted = lists:keysort(1, Normalized),
    Canonical = [[Name, $:, Value, $\n] || {Name, Value} <- Sorted],
    Signed = string:join([Name || {Name, _} <- Sorted], ";"),
    {Canonical, Signed}.

trimall(Value) ->
    %% TODO - remove excess internal whitespace in header values
    re:replace(Value, "(^\\s+)|(\\s+$)", "", [global]).

hash_encode(Data) ->
    Hash = crypto:hash(sha256, Data),
    base16(Hash).

base16(Data) ->
    io_lib:format("~64.16.0b", [binary:decode_unsigned(Data)]).

credential_scope(Date, Region, Service) ->
    DateOnly = string:left(Date, 8),
    [DateOnly, $/, Region, $/, Service, "/aws4_request"].
    
to_sign(Date, CredentialScope, Request) ->
    ["AWS4-HMAC-SHA256\n",
     Date, $\n,
     CredentialScope, $\n,
     hash_encode(Request)].
    
signing_key(Config, Date, Region, Service) ->
    %% TODO cache the signing key so we don't have to recompute for every request
    DateOnly = string:left(Date, 8),
    KDate = crypto:hmac(sha256, "AWS4" ++ Config#aws_config.secret_access_key, DateOnly),
    KRegion = crypto:hmac(sha256, KDate, Region),
    KService = crypto:hmac(sha256, KRegion, Service),
    crypto:hmac(sha256, KService, "aws4_request").
    
authorization(Config, CredentialScope, SignedHeaders, Signature) ->
    ["AWS4-HMAC-SHA256"
     " Credential=", Config#aws_config.access_key_id, $/, CredentialScope, $,,
     " SignedHeaders=", SignedHeaders, $,,
     " Signature=", Signature].
