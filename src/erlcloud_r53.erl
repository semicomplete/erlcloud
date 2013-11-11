%% @author Erick Gonzalez <erick@codemonkeylabs.de>
%% @doc Erlang interface to Amazon Route53 Service
%% [http://aws.amazon.com/de/route53/]
%%
-module(erlcloud_r53).
-export([change_record_sets/3]).
-include_lib("xmerl/include/xmerl.hrl").
-include_lib("erlcloud/include/erlcloud.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").
-include_lib("erlcloud/include/erlcloud_r53.hrl").

-define(API_VERSION, "2012-12-12").

%% @private
encode_resource_records(RecordSet) ->
    lists:foldl(
      fun(Record, A) ->
              [{'ResourceRecord',
                [{'Value',
                  [Record#r53_resource_record.value]}]} | A]
      end,
      [],
      RecordSet#r53_record_set.resource_records).

%% @private
encode_record_set(RecordSet) ->
    [{'Name', [RecordSet#r53_record_set.name]},
     {'Type', [RecordSet#r53_record_set.type]},
     {'TTL',  [integer_to_list(RecordSet#r53_record_set.ttl)]} |
     [{'ResourceRecords', encode_resource_records(RecordSet)}]].

%% @private
encode_changes(Actions) ->
    lists:foldl(
      fun ({Action, RecordSet}, A) ->
              [{'Change', 
                [{'Action', [Action]} |
                 [{'ResourceRecordSet', encode_record_set(RecordSet)}]]} | A]
      end,
      [],
      Actions).

%% @doc
%% Batches a DNS record set change request
-spec(change_record_sets(string(), {string(), r53_record_set()}, aws_config())
      -> {ok, proplist()} | {error, any()}).
change_record_sets(HostedZone, Actions, Conf) ->
    Host = Conf#aws_config.r53_host,
    Request = 
        [{'ChangeResourceRecordSetsRequest',
          [{xmlns, "https://" ++ Host ++ "/doc/" ++ ?API_VERSION ++ "/"}],
          [{'ChangeBatch',
            [{'Changes', encode_changes(Actions)}]}]}],
    XML = iolist_to_binary(xmerl:export_simple(Request, xmerl_xml)),
    R = r53_request(post, "/hostedzone/" ++ HostedZone ++ "/rrset", XML, Conf),
    case R of
        {ok, Response} ->
            Node = 
                hd(xmerl_xpath:string(
                     "/ChangeResourceRecordSetsResponse/ChangeInfo", Response)),
            {ok,
             [{change_id, erlcloud_xml:get_text("Id", Node)},
              {status,    erlcloud_xml:get_text("Status", Node)},
              {submitted, erlcloud_xml:get_text("SubmittedAt", Node)}]};
        Error -> Error
    end.

%% @private
r53_request(Method, Path, Body, Config) ->
    r53_request(Method, Path, "application/xml", Body, Config).
%% @private
r53_request(Method, Path, ContentType, Body, Config) ->
    URI = uri(Path, Config),
    send_request(Method, URI, auth_headers(Config), ContentType, Body).
%% @private
aws3_signature(String, Config) ->
    Mac = crypto:hmac(sha256, Config#aws_config.secret_access_key, String),
    lists:flatten(
      ["AWS3-HTTPS AWSAccessKeyId=",
       Config#aws_config.access_key_id,
       [$, | "Algorithm=HmacSHA256,Signature="],
       binary_to_list(base64:encode(Mac))]).
%% @private
uri(Path, Config) -> 
    Host = Config#aws_config.r53_host,
    "https://" ++ Host ++ [$/ | ?API_VERSION] ++ Path.
%% @private
auth_headers(Config) ->
    Date = httpd_util:rfc1123_date(erlang:localtime()),
    [{"Date",                 Date},
     {"X-Amzn-Authorization", aws3_signature(Date, Config)}].

%% @private    
send_request(Method, URI) when is_list(URI) ->
    send_request(Method, URI, []);    
send_request(Method, Request) when is_tuple(Request) ->
    Response = httpc:request(Method, Request, [], []),
    case erlcloud_aws:http_headers_body(Response) of 
        {ok, {_, Body}} ->
            {ok, element(1, xmerl_scan:string(Body))};
        {error, {http_error, StatusCode, StatusMsg, Body}} ->
            XML = element(1, xmerl_scan:string(Body)),
            case XML of
                #xmlElement{name='ErrorResponse'} ->
                    Node = hd(xmerl_xpath:string("/ErrorResponse/Error", XML)),
                    Code = erlcloud_xml:get_text("Code", Node),
                    Msg  = erlcloud_xml:get_text("Message", Node),
                    {error, [{type, Code},
                             {reason, Msg}]};                    
                _ ->
                    {error, [{type, StatusCode},
                             {reason, StatusMsg}],
                     Body}
            end;
        Error -> Error
    end.
                    
%% @private
send_request(Method, URI, Headers) ->
    send_request(Method, {URI, Headers}).
%% @private
send_request(Method, URI, Headers, ContentType, Body) ->
    send_request(Method, {URI, Headers, ContentType, Body}).

