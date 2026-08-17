package model

import "time"

type Classification string

const (
	ClassBenign     Classification = "benign"
	ClassSuspicious Classification = "suspicious"
	ClassHostile    Classification = "hostile"
)

type ActorType string

const (
	ActorUnknown   ActorType = "unknown"
	ActorHuman     ActorType = "human"
	ActorAutomated ActorType = "automated"
)

type Session struct {
	ID               string         `json:"id"`
	IP               string         `json:"ip"`
	IPSource         string         `json:"ip_source,omitempty"`
	Proxy            string         `json:"proxy,omitempty"`
	Country          string         `json:"country,omitempty"`
	CountrySource    string         `json:"country_source,omitempty"`
	CloudflareRay    string         `json:"cloudflare_ray,omitempty"`
	CloudflareColo   string         `json:"cloudflare_colo,omitempty"`
	FirstPath        string         `json:"first_path,omitempty"`
	FirstReferrer    string         `json:"first_referrer,omitempty"`
	LastReferrer     string         `json:"last_referrer,omitempty"`
	ReferrerHost     string         `json:"referrer_host,omitempty"`
	RequestHost      string         `json:"request_host,omitempty"`
	Target           string         `json:"target,omitempty"`
	TargetTrust      string         `json:"target_trust,omitempty"`
	HostSweep        bool           `json:"host_sweep,omitempty"`
	HostSweepHosts   int            `json:"host_sweep_hosts,omitempty"`
	Origin           string         `json:"origin,omitempty"`
	AcceptLanguage   string         `json:"accept_language,omitempty"`
	HTTPProtocol     string         `json:"http_protocol,omitempty"`
	Integration      string         `json:"integration,omitempty"`
	IntegrationTrust string         `json:"integration_trust,omitempty"`
	CatchAll         bool           `json:"catch_all,omitempty"`
	UserAgent        string         `json:"user_agent"`
	BotProvider      string         `json:"bot_provider,omitempty"`
	BotName          string         `json:"bot_name,omitempty"`
	BotVerified      bool           `json:"bot_verified,omitempty"`
	BotClaimed       bool           `json:"bot_claimed,omitempty"`
	FirstSeen        time.Time      `json:"first_seen"`
	LastSeen         time.Time      `json:"last_seen"`
	RequestCount     int            `json:"request_count"`
	LoginAttempts    int            `json:"login_attempts,omitempty"`
	VisitCount       int            `json:"visit_count"`
	VisitStarted     time.Time      `json:"visit_started"`
	RiskScore        int            `json:"risk_score"`
	AutomationScore  int            `json:"automation_score"`
	Classification   Classification `json:"classification"`
	Actor            ActorType      `json:"actor"`
	Confidence       string         `json:"confidence"`
	AvgIntervalMS    int64          `json:"avg_interval_ms"`
	IntervalVarMS    int64          `json:"interval_variance_ms"`
	Depth            int            `json:"depth"`
	Loop             int            `json:"loop"`
	Frustration      int            `json:"frustration"`
	CurrentPath      string         `json:"current_path"`
	Persona          string         `json:"persona"`
	LastStatus       int            `json:"last_status"`
	LastMethod       string         `json:"last_method"`
	RecentTimes      []time.Time    `json:"-"`
	Journey          []JourneyStep  `json:"journey"`
}

type JourneyStep struct {
	At    time.Time `json:"at"`
	Path  string    `json:"path"`
	Label string    `json:"label"`
}

type SessionDetail struct {
	Session Session `json:"session"`
	Events  []Event `json:"events"`
}

type WebSessionExport struct {
	ExportedAt time.Time `json:"exported_at"`
	Version    string    `json:"version"`
	Session    Session   `json:"session"`
	Events     []Event   `json:"events"`
}

type Event struct {
	ID                  string         `json:"id"`
	At                  time.Time      `json:"at"`
	SessionID           string         `json:"session_id"`
	SessionFirstSeen    time.Time      `json:"session_first_seen,omitempty"`
	SessionRequests     int            `json:"session_requests,omitempty"`
	SessionVisits       int            `json:"session_visits,omitempty"`
	SessionVisitStarted time.Time      `json:"session_visit_started,omitempty"`
	IP                  string         `json:"ip"`
	IPSource            string         `json:"ip_source,omitempty"`
	Proxy               string         `json:"proxy,omitempty"`
	Country             string         `json:"country,omitempty"`
	CountrySource       string         `json:"country_source,omitempty"`
	CloudflareRay       string         `json:"cloudflare_ray,omitempty"`
	CloudflareColo      string         `json:"cloudflare_colo,omitempty"`
	Referrer            string         `json:"referrer,omitempty"`
	ReferrerHost        string         `json:"referrer_host,omitempty"`
	RequestHost         string         `json:"request_host,omitempty"`
	Target              string         `json:"target,omitempty"`
	TargetTrust         string         `json:"target_trust,omitempty"`
	HostSweep           bool           `json:"host_sweep,omitempty"`
	HostSweepHosts      int            `json:"host_sweep_hosts,omitempty"`
	ProbeName           string         `json:"probe_name,omitempty"`
	ProbeProduct        string         `json:"probe_product,omitempty"`
	ProbeCVE            string         `json:"probe_cve,omitempty"`
	KnownProbe          bool           `json:"known_probe,omitempty"`
	Origin              string         `json:"origin,omitempty"`
	AcceptLanguage      string         `json:"accept_language,omitempty"`
	HTTPProtocol        string         `json:"http_protocol,omitempty"`
	Integration         string         `json:"integration,omitempty"`
	IntegrationTrust    string         `json:"integration_trust,omitempty"`
	CatchAll            bool           `json:"catch_all,omitempty"`
	Method              string         `json:"method"`
	Path                string         `json:"path"`
	Status              int            `json:"status"`
	Bytes               int            `json:"bytes"`
	RiskScore           int            `json:"risk_score"`
	AutomationScore     int            `json:"automation_score"`
	Classification      Classification `json:"classification"`
	Actor               ActorType      `json:"actor"`
	Confidence          string         `json:"confidence,omitempty"`
	AvgIntervalMS       int64          `json:"avg_interval_ms,omitempty"`
	IntervalVarMS       int64          `json:"interval_variance_ms,omitempty"`
	Persona             string         `json:"persona,omitempty"`
	Depth               int            `json:"depth"`
	Loop                int            `json:"loop"`
	Frustration         int            `json:"frustration"`
	Category            string         `json:"category"`
	Message             string         `json:"message"`
	UserAgent           string         `json:"user_agent,omitempty"`
	BotProvider         string         `json:"bot_provider,omitempty"`
	BotName             string         `json:"bot_name,omitempty"`
	BotVerified         bool           `json:"bot_verified,omitempty"`
	BotClaimed          bool           `json:"bot_claimed,omitempty"`
}

type RealtimeMessage struct {
	Type       string      `json:"type"`
	At         time.Time   `json:"at"`
	Event      *Event      `json:"event,omitempty"`
	Session    *Session    `json:"session,omitempty"`
	SSHEvent   *SSHEvent   `json:"ssh_event,omitempty"`
	SSHSession *SSHSession `json:"ssh_session,omitempty"`
}

type Overview struct {
	Now            time.Time `json:"now"`
	UptimeSeconds  int64     `json:"uptime_seconds"`
	ActiveSessions int       `json:"active_sessions"`
	Benign         int       `json:"benign"`
	Suspicious     int       `json:"suspicious"`
	Hostile        int       `json:"hostile"`
	Human          int       `json:"human"`
	Automated      int       `json:"automated"`
	Unknown        int       `json:"unknown"`
	RequestsTotal  int64     `json:"requests_total"`
	RequestsToday  int64     `json:"requests_today"`
	RequestsPerSec float64   `json:"requests_per_sec"`
	AvgDepth       float64   `json:"avg_depth"`
	LoopsTotal     int64     `json:"loops_total"`
	TopPaths       []Count   `json:"top_paths"`
	RiskBuckets    []Count   `json:"risk_buckets"`
	PersonaCounts  []Count   `json:"persona_counts"`
	TopCountries   []Count   `json:"top_countries"`
	TopReferrers   []Count   `json:"top_referrers"`
	TopTargets     []Count   `json:"top_targets"`
}

type Count struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type TrustedDomain struct {
	Domain      string    `json:"domain"`
	Source      string    `json:"source"`
	Integration string    `json:"integration,omitempty"`
	AddedAt     time.Time `json:"added_at"`
}

type TrustedDomainSettings struct {
	Manual []TrustedDomain `json:"manual"`
	Proxy  []TrustedDomain `json:"proxy"`
}

type UntrustedHostStat struct {
	Host          string    `json:"host"`
	Requests      int64     `json:"requests"`
	Sources       int       `json:"sources"`
	SweepRequests int64     `json:"sweep_requests"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

type UntrustedHostOverview struct {
	RequestsTotal int64               `json:"requests_total"`
	HostsTotal    int                 `json:"hosts_total"`
	SweepRequests int64               `json:"sweep_requests"`
	Hosts         []UntrustedHostStat `json:"hosts"`
}

type ProbeStat struct {
	Name               string    `json:"name"`
	Product            string    `json:"product,omitempty"`
	CVE                string    `json:"cve,omitempty"`
	Count              int64     `json:"count"`
	HostileRequests    int64     `json:"hostile_requests"`
	SuspiciousRequests int64     `json:"suspicious_requests"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
}

type RecentPath struct {
	Path           string         `json:"path"`
	Method         string         `json:"method,omitempty"`
	Count          int64          `json:"count"`
	FirstSeen      time.Time      `json:"first_seen"`
	LastSeen       time.Time      `json:"last_seen"`
	Status         int            `json:"status"`
	Classification Classification `json:"classification"`
	Kind           string         `json:"kind"`
	ProbeName      string         `json:"probe_name,omitempty"`
}

type UnknownPath struct {
	Path             string    `json:"path"`
	Method           string    `json:"method,omitempty"`
	Count            int64     `json:"count"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	ExampleIP        string    `json:"example_ip,omitempty"`
	ExampleUserAgent string    `json:"example_user_agent,omitempty"`
}

type CatchAllHost struct {
	Host               string    `json:"host"`
	Requests           int64     `json:"requests"`
	HostileRequests    int64     `json:"hostile_requests"`
	SuspiciousRequests int64     `json:"suspicious_requests"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
	LastIntegration    string    `json:"last_integration,omitempty"`
}

type CatchAllOverview struct {
	RequestsTotal   int64          `json:"requests_total"`
	HostsTotal      int            `json:"hosts_total"`
	Hosts           []CatchAllHost `json:"hosts"`
	TopIntegrations []Count        `json:"top_integrations"`
}

type IntegrationPeer struct {
	Name         string    `json:"name"`
	SourceIP     string    `json:"source_ip,omitempty"`
	Trust        string    `json:"trust,omitempty"`
	Status       string    `json:"status"`
	FirstSeen    time.Time `json:"first_seen"`
	LastVerified time.Time `json:"last_verified"`
	LastFailure  time.Time `json:"last_failure,omitempty"`
	Checks       int64     `json:"checks"`
	Failures     int64     `json:"failures"`
	LastError    string    `json:"last_error,omitempty"`
}

type ActorActivity struct {
	At          time.Time `json:"at"`
	Protocol    string    `json:"protocol"`
	Kind        string    `json:"kind"`
	SessionID   string    `json:"session_id,omitempty"`
	Summary     string    `json:"summary"`
	Path        string    `json:"path,omitempty"`
	Command     string    `json:"command,omitempty"`
	Family      string    `json:"family,omitempty"`
	RiskScore   int       `json:"risk_score,omitempty"`
	Depth       int       `json:"depth,omitempty"`
	Canary      string    `json:"canary,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

type ActorProfile struct {
	ID                      string         `json:"id"`
	IP                      string         `json:"ip"`
	Country                 string         `json:"country,omitempty"`
	FirstSeen               time.Time      `json:"first_seen"`
	LastSeen                time.Time      `json:"last_seen"`
	HTTPRequests            int64          `json:"http_requests"`
	SSHConnections          int64          `json:"ssh_connections"`
	SSHCommands             int64          `json:"ssh_commands"`
	Protocols               []string       `json:"protocols"`
	RiskScore               int            `json:"risk_score"`
	Depth                   int            `json:"depth"`
	Classification          Classification `json:"classification"`
	Actor                   ActorType      `json:"actor"`
	EngagementSeconds       int64          `json:"engagement_seconds"`
	CanaryTouches           int64          `json:"canary_touches"`
	PayloadAttempts         int64          `json:"payload_attempts"`
	Fingerprints            []string       `json:"fingerprints,omitempty"`
	SSHMedianRevisitSeconds int64          `json:"ssh_median_revisit_seconds,omitempty"`
	SSHRevisitJitterSeconds int64          `json:"ssh_revisit_jitter_seconds,omitempty"`
	SSHAuthAccepted         int64          `json:"ssh_auth_accepted,omitempty"`
	SSHAuthRejected         int64          `json:"ssh_auth_rejected,omitempty"`
	SSHUniqueUsers          int            `json:"ssh_unique_users,omitempty"`
	SSHPeakConcurrent       int            `json:"ssh_peak_concurrent,omitempty"`
	SSHPeakAttemptsPerMin   int            `json:"ssh_peak_attempts_per_minute,omitempty"`
}

type ActorDetail struct {
	Actor    ActorProfile    `json:"actor"`
	Timeline []ActorActivity `json:"timeline"`
}

type IPActivityBucket struct {
	At   time.Time `json:"at"`
	HTTP int64     `json:"http"`
	SSH  int64     `json:"ssh"`
}

type IPTopValue struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type IPCampaignPeer struct {
	IP         string    `json:"ip"`
	Country    string    `json:"country,omitempty"`
	Confidence int       `json:"confidence"`
	RiskScore  int       `json:"risk_score"`
	LastSeen   time.Time `json:"last_seen"`
	Reasons    []string  `json:"reasons"`
}

type IPIntelligenceSummary struct {
	FirstSeen                 time.Time `json:"first_seen"`
	LastSeen                  time.Time `json:"last_seen"`
	RiskScore                 int       `json:"risk_score"`
	Classification            string    `json:"classification"`
	Actor                     string    `json:"actor"`
	HTTPRequests              int64     `json:"http_requests"`
	HTTPUniquePaths           int       `json:"http_unique_paths"`
	HTTPUniqueTargets         int       `json:"http_unique_targets"`
	HTTPPeakRequestsPerMinute int       `json:"http_peak_requests_per_minute"`
	SSHConnections            int64     `json:"ssh_connections"`
	SSHAuthAccepted           int64     `json:"ssh_auth_accepted"`
	SSHAuthRejected           int64     `json:"ssh_auth_rejected"`
	SSHUniqueUsers            int       `json:"ssh_unique_users"`
	SSHUniqueClients          int       `json:"ssh_unique_clients"`
	SSHCommands               int64     `json:"ssh_commands"`
	SSHPeakConcurrent         int       `json:"ssh_peak_concurrent"`
	SSHPeakAttemptsPerMinute  int       `json:"ssh_peak_attempts_per_minute"`
	SSHMedianRevisitSeconds   int64     `json:"ssh_median_revisit_seconds"`
	SSHRevisitJitterSeconds   int64     `json:"ssh_revisit_jitter_seconds"`
	PayloadSignals            int64     `json:"payload_signals"`
	CanaryTouches             int64     `json:"canary_touches"`
	EngagementSeconds         int64     `json:"engagement_seconds"`
	Depth                     int       `json:"depth"`
	Reasons                   []string  `json:"reasons"`
}

type IPIntelligence struct {
	ExportedAt    time.Time             `json:"exported_at"`
	Version       string                `json:"version"`
	IP            string                `json:"ip"`
	Actor         ActorProfile          `json:"actor"`
	Summary       IPIntelligenceSummary `json:"summary"`
	Timeline      []IPActivityBucket    `json:"timeline"`
	TopUsernames  []IPTopValue          `json:"top_usernames"`
	TopSSHClients []IPTopValue          `json:"top_ssh_clients"`
	TopCommands   []IPTopValue          `json:"top_commands"`
	TopFamilies   []IPTopValue          `json:"top_command_families"`
	TopPaths      []IPTopValue          `json:"top_paths"`
	TopTargets    []IPTopValue          `json:"top_targets"`
	CampaignPeers []IPCampaignPeer      `json:"possible_campaign_peers"`
	HTTPSessions  []Session             `json:"http_sessions"`
	HTTPEvents    []Event               `json:"http_events"`
	SSHSessions   []SSHSession          `json:"ssh_sessions"`
	SSHEvents     []SSHEvent            `json:"ssh_events"`
	Intelligence  []IntelSignal         `json:"intelligence"`
}

type ActorOverview struct {
	ActorsTotal       int64   `json:"actors_total"`
	CrossProtocol     int64   `json:"cross_protocol"`
	EngagementSeconds int64   `json:"engagement_seconds"`
	CanaryTouches     int64   `json:"canary_touches"`
	PayloadAttempts   int64   `json:"payload_attempts"`
	TopFingerprints   []Count `json:"top_fingerprints"`
}

type IntelSignal struct {
	ID        string    `json:"id"`
	At        time.Time `json:"at"`
	ActorID   string    `json:"actor_id"`
	IP        string    `json:"ip"`
	Protocol  string    `json:"protocol"`
	SessionID string    `json:"session_id,omitempty"`
	Kind      string    `json:"kind"`
	Tool      string    `json:"tool,omitempty"`
	Technique string    `json:"technique,omitempty"`
	URL       string    `json:"url,omitempty"`
	Host      string    `json:"host,omitempty"`
	Filename  string    `json:"filename,omitempty"`
	Canary    string    `json:"canary,omitempty"`
	Summary   string    `json:"summary"`
}

type IntelSummary struct {
	Indicator string    `json:"indicator"`
	Kind      string    `json:"kind"`
	Protocols []string  `json:"protocols"`
	Tools     []string  `json:"tools,omitempty"`
	Count     int64     `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type HealthOverview struct {
	HTTPRejected               int64  `json:"http_rejected"`
	SSHRejectedGlobal          int64  `json:"ssh_rejected_global"`
	SSHRejectedPerIP           int64  `json:"ssh_rejected_per_ip"`
	SSHTarpitApplied           int64  `json:"ssh_tarpit_applied"`
	SSHCommandBudgetHits       int64  `json:"ssh_command_budget_hits"`
	SSHVirtualStorageHits      int64  `json:"ssh_virtual_storage_hits"`
	SSHRecursionGuardHits      int64  `json:"ssh_recursion_guard_hits"`
	RealtimeSubscriberRejected int64  `json:"realtime_subscriber_rejected"`
	EventsBytes                int64  `json:"events_bytes"`
	SSHEventsBytes             int64  `json:"ssh_events_bytes"`
	IntelEventsBytes           int64  `json:"intel_events_bytes"`
	StorageTotalBytes          int64  `json:"storage_total_bytes"`
	StorageWarnBytes           int64  `json:"storage_warn_bytes"`
	StorageCriticalBytes       int64  `json:"storage_critical_bytes"`
	StoragePressure            string `json:"storage_pressure"`
	StorageCompactions         int64  `json:"storage_compactions"`
	HTTPEventsInMemory         int    `json:"http_events_in_memory"`
	SSHEventsInMemory          int    `json:"ssh_events_in_memory"`
	IntelEventsInMemory        int    `json:"intel_events_in_memory"`
	HTTPSessionsInMemory       int    `json:"http_sessions_in_memory"`
	SSHSessionsInMemory        int    `json:"ssh_sessions_in_memory"`
	ActorsInMemory             int    `json:"actors_in_memory"`
	RealtimeSubscribers        int    `json:"realtime_subscribers"`
	RealtimeSubscriberLimit    int    `json:"realtime_subscriber_limit"`
}

type SSHSession struct {
	ID              string         `json:"id"`
	IP              string         `json:"ip"`
	Country         string         `json:"country,omitempty"`
	CountrySource   string         `json:"country_source,omitempty"`
	ClientVersion   string         `json:"client_version,omitempty"`
	Username        string         `json:"username,omitempty"`
	FirstSeen       time.Time      `json:"first_seen"`
	LastSeen        time.Time      `json:"last_seen"`
	DisconnectedAt  time.Time      `json:"disconnected_at,omitempty"`
	AuthAttempts    int            `json:"auth_attempts"`
	AuthAccepted    bool           `json:"auth_accepted"`
	ShellOpened     bool           `json:"shell_opened"`
	ExecRequests    int            `json:"exec_requests"`
	CommandCount    int            `json:"command_count"`
	CurrentCommand  string         `json:"current_command,omitempty"`
	LastAction      string         `json:"last_action,omitempty"`
	CurrentDir      string         `json:"current_dir,omitempty"`
	Depth           int            `json:"depth"`
	Loop            int            `json:"loop"`
	Frustration     int            `json:"frustration"`
	Persona         string         `json:"persona,omitempty"`
	RiskScore       int            `json:"risk_score"`
	Classification  Classification `json:"classification"`
	Actor           ActorType      `json:"actor"`
	Active          bool           `json:"active"`
	DurationSeconds int64          `json:"duration_seconds"`
}

type SSHEvent struct {
	ID               string         `json:"id"`
	At               time.Time      `json:"at"`
	SessionID        string         `json:"session_id"`
	IP               string         `json:"ip"`
	Country          string         `json:"country,omitempty"`
	CountrySource    string         `json:"country_source,omitempty"`
	ClientVersion    string         `json:"client_version,omitempty"`
	Username         string         `json:"username,omitempty"`
	Type             string         `json:"type"`
	AuthMethod       string         `json:"auth_method,omitempty"`
	AuthAccepted     bool           `json:"auth_accepted,omitempty"`
	PasswordSupplied bool           `json:"password_supplied,omitempty"`
	PasswordLength   int            `json:"password_length,omitempty"`
	KeyFingerprint   string         `json:"key_fingerprint,omitempty"`
	Command          string         `json:"command,omitempty"`
	CommandName      string         `json:"command_name,omitempty"`
	CommandFamily    string         `json:"command_family,omitempty"`
	CWD              string         `json:"cwd,omitempty"`
	Output           string         `json:"output,omitempty"`
	Depth            int            `json:"depth,omitempty"`
	Loop             int            `json:"loop,omitempty"`
	Frustration      int            `json:"frustration,omitempty"`
	Persona          string         `json:"persona,omitempty"`
	RiskScore        int            `json:"risk_score,omitempty"`
	Classification   Classification `json:"classification,omitempty"`
	Actor            ActorType      `json:"actor,omitempty"`
	Message          string         `json:"message,omitempty"`
	CanaryTouches    []string       `json:"canary_touches,omitempty"`
	Fingerprint      string         `json:"fingerprint,omitempty"`
	StdinBytes       int            `json:"stdin_bytes,omitempty"`
	StdinSHA256      string         `json:"stdin_sha256,omitempty"`
	StdinKind        string         `json:"stdin_kind,omitempty"`
	PayloadStage     string         `json:"payload_stage,omitempty"`
	PayloadPath      string         `json:"payload_path,omitempty"`
	NetworkTarget    string         `json:"network_target,omitempty"`
	NetworkPort      int            `json:"network_port,omitempty"`
}

type SSHOverview struct {
	Enabled           bool    `json:"enabled"`
	ActiveSessions    int     `json:"active_sessions"`
	ConnectionsTotal  int64   `json:"connections_total"`
	ConnectionsToday  int64   `json:"connections_today"`
	AuthAttemptsTotal int64   `json:"auth_attempts_total"`
	AuthAttemptsToday int64   `json:"auth_attempts_today"`
	ShellsTotal       int64   `json:"shells_total"`
	ShellsToday       int64   `json:"shells_today"`
	CommandsTotal     int64   `json:"commands_total"`
	CommandsToday     int64   `json:"commands_today"`
	AvgDepth          float64 `json:"avg_depth"`
	TopUsers          []Count `json:"top_users"`
	TopCommands       []Count `json:"top_commands"`
	TopFamilies       []Count `json:"top_families"`
	TopCountries      []Count `json:"top_countries"`
	TopClients        []Count `json:"top_clients"`
}

type SSHSessionDetail struct {
	Session SSHSession `json:"session"`
	Events  []SSHEvent `json:"events"`
}

type SSHLiveFeedItem struct {
	Session SSHSession `json:"session"`
	Events  []SSHEvent `json:"events"`
}

// SSHHighlight is a compact, derived view of a noteworthy authenticated SSH session.
// Transcript data stays in ssh-events.jsonl and is intentionally not duplicated here.
type SSHHighlight struct {
	SessionID       string    `json:"session_id"`
	At              time.Time `json:"at"`
	LastSeen        time.Time `json:"last_seen"`
	IP              string    `json:"ip"`
	Country         string    `json:"country,omitempty"`
	Username        string    `json:"username,omitempty"`
	Score           int       `json:"score"`
	Rating          string    `json:"rating"`
	Title           string    `json:"title"`
	Reason          string    `json:"reason"`
	Tags            []string  `json:"tags,omitempty"`
	Commands        int       `json:"commands"`
	DurationSeconds int64     `json:"duration_seconds"`
	Depth           int       `json:"depth"`
	Signals         []string  `json:"signals,omitempty"`
}

type SSHHighlightPage struct {
	Items      []SSHHighlight `json:"items"`
	NextBefore string         `json:"next_before,omitempty"`
}

type SSHSessionExport struct {
	ExportedAt time.Time     `json:"exported_at"`
	Version    string        `json:"version"`
	Session    SSHSession    `json:"session"`
	Events     []SSHEvent    `json:"events"`
	Actor      *ActorProfile `json:"actor,omitempty"`
	Intel      []IntelSignal `json:"intel,omitempty"`
}

type ScanBurst struct {
	ID          string    `json:"id"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Target      string    `json:"target,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	SourceGroup string    `json:"source_group,omitempty"`
	Sources     int       `json:"sources"`
	Requests    int       `json:"requests"`
	Paths       []string  `json:"paths,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}
