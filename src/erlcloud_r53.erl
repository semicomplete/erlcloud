%% @author Erick Gonzalez <erick@codemonkeylabs.de>
%% @doc Erlang interface to Amazon Route53 Service
%% [http://aws.amazon.com/de/route53/]
%%
-module(erlcloud_r53).
-export([change_record_sets/3]).
-export([create_hosted_zone/3, create_hosted_zone/4]).
-export([delete_hosted_zone/2]).
-export([get_hosted_zone/2]).
-export([get_record_set/3, get_record_set/4]).
-export([list_hosted_zones/1]).
-export([list_record_sets/3, list_record_sets/4, list_record_sets/6]).
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
%% Creates a new Hosted Zone
-spec(create_hosted_zone(string(), string(), aws_config()) -> 
             {ok, proplist()} | {error, any()}).
create_hosted_zone(Name, Reference, Config) ->
    create_hosted_zone(Name, Reference, "", Config).
-spec(create_hosted_zone(string(), string(), string(), aws_config()) -> 
             {ok, proplist()} | {error, any()}).
create_hosted_zone(Name, Reference, Comment, Config) ->
    Tag         = 'CreateHostedZoneRequest',
    Path        = "/hostedzone",
    Request     = [{'Name', [Name]},
                   {'CallerReference', [Reference]},
                   {'HostedZoneConfig', 
                    [{'Comment', [Comment]}]}],
    ResponseTag = "CreateHostedZoneResponse",
    case r53_send_request(post, Tag, Path, Request, ResponseTag, Config) of
        {ok, _Node, Response} ->
            {ok, Response};
        Error -> Error
    end.

%% @doc
%% Deletes a Hosted Zone
-spec(delete_hosted_zone(string(), aws_config()) ->
             {ok, proplist()} | {error, any()}).
delete_hosted_zone(Name, Config) ->
    Path        = "/hostedzone/" ++ Name,
    ResponseTag = "DeleteHostedZoneResponse",
    r53_send_request(delete, Path, ResponseTag, Config).

%% @doc
%% Batches a DNS record set change request
-spec(change_record_sets(string(), {string(), r53_record_set()}, aws_config())
      -> {ok, proplist()} | {error, any()}).
change_record_sets(HostedZone, Actions, Config) ->
    Tag         = 'ChangeResourceRecordSetsRequest',
    Path        = "/hostedzone/" ++ HostedZone ++ "/rrset",
    Request     = [{'ChangeBatch',
                    [{'Changes', encode_changes(Actions)}]}],
    ResponseTag = "ChangeResourceRecordSetsResponse",
    case r53_send_request(post, Tag, Path, Request, ResponseTag, Config) of
        {ok, _Node, Response} ->
            {ok, Response};
        Error -> Error
    end.

%% @private
extract_hosted_zone(Node0) ->
    Node = hd(xmerl_xpath:string("/HostedZone", Node0)),
    [{id,           erlcloud_xml:get_text("Id",                        Node)},
     {name,         erlcloud_xml:get_text("Name",                      Node)},
     {comment,      erlcloud_xml:get_text("Config/Comment",            Node)},
     {record_count, erlcloud_xml:get_integer("ResourceRecordSetCount", Node)}].

%% @private
extract_hosted_zones(Node) ->
    Zones = xmerl_xpath:string("/HostedZones/*", Node),
    [{hosted_zones, lists:map(fun extract_hosted_zone/1,    Zones)},
     {marker,       erlcloud_xml:get_text("Marker",         Node)},
     {is_truncated, erlcloud_xml:get_bool("IsTruncated",    Node)},
     {next_marker,  erlcloud_xml:get_text("NextMarker",     Node)},
     {max_items,    erlcloud_xml:get_integer("MaxItems",    Node)}].

%% @private
extract_delegation_set(Node) ->
    NSNodes =
        lists:foldl(
          fun(N, A) ->
                  [erlcloud_xml:get_text("/NameServer", N) | A] 
          end,
          [],
          xmerl_xpath:string("/DelegationSet/NameServers/*", Node)),
    [{nameservers, NSNodes}].

%% @private
extract_change_info(Node) ->
    [{change_id, erlcloud_xml:get_text("Id", Node)},
     {status,    erlcloud_xml:get_text("Status", Node)},
     {submitted, erlcloud_xml:get_text("SubmittedAt", Node)}].

%% @private
extract_record(Node) ->
    Values = xmerl_xpath:string("ResourceRecord/*", Node),
    lists:map(fun(V) -> erlcloud_xml:get_text("/Value", V) end, Values).
    
%% @private
extract_record_set(Node0) ->
    Node    = hd(xmerl_xpath:string("/ResourceRecordSet", Node0)),
    Records = xmerl_xpath:string("ResourceRecords", Node),
    [{name, erlcloud_xml:get_text("Name", Node)},
     {type, erlcloud_xml:get_text("Type", Node)},
     {ttl,  erlcloud_xml:get_text("TTL",  Node)},
     {records, lists:map(fun extract_record/1, Records)},
     {health_check_id, erlcloud_xml:get_text("HealthCheckId", Node)}].

%% @private
extract_record_sets(Node) ->
    Records = xmerl_xpath:string("ResourceRecordSets/*", Node),
    [{record_sets,      lists:map(fun extract_record_set/1, Records)},
     {is_truncated,     erlcloud_xml:get_bool("IsTruncated",          Node)},
     {max_items,        erlcloud_xml:get_integer("MaxItems",          Node)},
     {next_record_name, erlcloud_xml:get_text("NextRecordName",       Node)},
     {next_record_type, erlcloud_xml:get_text("NextRecordType",       Node)},
     {next_record_id,   erlcloud_xml:get_text("NextRecordIdentifier", Node)}].

%% @doc
%% Get information pertaining to a specific hosted zone
-spec(get_hosted_zone(string(), aws_config()) -> 
             {ok, proplist()} | {error, any()}).
get_hosted_zone(Name, Config) ->
    Path        = "/hostedzone/" ++ Name,
    ResponseTag = "GetHostedZoneResponse",
    case r53_send_request(get, Path, ResponseTag, Config) of
        {ok, Node} ->
            Zone = hd(xmerl_xpath:string("HostedZone", Node)),
            DS   = hd(xmerl_xpath:string("DelegationSet", Node)),
            {ok, 
             [{hosted_zone,    extract_hosted_zone(Zone)},
              {delegation_set, extract_delegation_set(DS)}]};
        Error -> Error
    end.

%% @doc
%% Retrieves a specific record set
-spec(get_record_set(string(), string(), string(), aws_config()) ->
             {ok, proplist()} | {error, any()}).
get_record_set(HostedZone, Name, Type, Config) ->
    list_record_sets(HostedZone, Name, Type, undefined, 1, Config).

%% @doc
%% Retrieve a list of all record sets of given name
-spec(get_record_set(string(), string(), aws_config()) ->
 {ok, proplist()} | {error, any()}).
get_record_set(HostedZone, Name, Config) ->
    get_record_set(HostedZone, Name, undefined, Config).

%% @doc
%% Retrieve a list of record sets for the given name
-spec(list_record_sets(string(), string(), aws_config()) -> 
             {ok, proplist()} | {error, any()}).
list_record_sets(HostedZone, Name, Config) ->
    list_record_sets(HostedZone, Name, undefined, undefined, undefined, Config).

%% @doc
%% Retrieve a list of record sets for the given name and type
-spec(list_record_sets(string(), string(), string(), aws_config()) -> 
             {ok, proplist()} | {error, any()}).
list_record_sets(HostedZone, Start, Type, Config) ->
    list_record_sets(HostedZone, Start, Type, undefined, undefined, Config).

%% @doc
%% Retrieve a list of N record sets starting from the specified entry
-spec(list_record_sets(string(), string(), string(), string(), number(), 
                       aws_config()) -> {ok, proplist()} | {error, any()}).
list_record_sets(HostedZone, Start, Type, SetIdentifier, Count, Config) ->
    Path        = "/hostedzone/" ++ HostedZone ++ "/rrset",
    Params      = erlcloud_aws:param_list_r([{"name",       Start},
                                             {"type",       Type},
                                             {"identifier", SetIdentifier},
                                             {"maxitems",   Count}]),
    Query       = erlcloud_http:make_query_string(Params),
    URI         = Path ++ [$? | Query],
    ResponseTag = "ListResourceRecordSetsResponse",
    case r53_send_request(get, URI, ResponseTag, Config) of
        {ok, Node} ->
            {ok, extract_record_sets(Node)};
        Error -> Error
    end.

%% @doc
%% List all hosted zones
-spec(list_hosted_zones(aws_config()) 
      -> {ok, proplist()} | {error, any()}).
list_hosted_zones(Config) ->
    Path        = "/hostedzone",
    ResponseTag = "ListHostedZonesResponse",
    case r53_send_request(get, Path, ResponseTag, Config) of
        {ok, Node} ->
            Zones = hd(xmerl_xpath:string("HostedZones", Node)),
            {ok, extract_hosted_zones(Zones)};
        Error -> Error
    end.
%% @private
r53_send_request(Method, RequestTag, Path, Request, ResponseTag, Config) 
  when is_atom(RequestTag) and is_list(ResponseTag) ->
    Host = Config#aws_config.r53_host,
    R = [{RequestTag, 
          [{xmlns, "https://" ++ Host ++ "/doc/" ++ ?API_VERSION ++ "/"}],
          Request}],
    XML = iolist_to_binary(xmerl:export_simple(R, xmerl_xml)),
    case r53_request(Method, Path, XML, Config) of
        {ok, Response} ->
            Node   = hd(xmerl_xpath:string([$/ | ResponseTag], Response)),
            CINode = hd(xmerl_xpath:string("ChangeInfo", Node)),
            {ok, Node, extract_change_info(CINode)};
        Error -> Error
    end.

%% @private
r53_send_request(Method, Path, ResponseTag, Config) ->
         case r53_request(Method, Path, Config) of
             {ok, Response} ->
                 XPath = [$/ | ResponseTag],
                 Node = hd(xmerl_xpath:string(XPath, Response)),
                 case Method of 
                     get -> {ok, Node};
                     delete ->
                         CINode = hd(xmerl_xpath:string("ChangeInfo", Node)),
                         {ok, extract_change_info(CINode)}
                 end;
             Error -> Error
         end.

%% @private
r53_request(Method, Path, Config) ->
    URI = uri(Path, Config),
    send_request(Method, URI, auth_headers(Config)).
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

