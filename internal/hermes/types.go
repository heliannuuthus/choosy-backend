package hermes

// ServiceCreateRequest 创建服务请求
type ServiceCreateRequest struct {
	ServiceID             string  `json:"service_id" binding:"required"`
	DomainID              string  `json:"domain_id" binding:"required"`
	Name                  string  `json:"name" binding:"required"`
	Description           *string `json:"description"`
	AccessTokenExpiresIn  *int    `json:"access_token_expires_in"`
	RefreshTokenExpiresIn *int    `json:"refresh_token_expires_in"`
}

// ServiceUpdateRequest 更新服务请求
type ServiceUpdateRequest struct {
	Name                  *string `json:"name"`
	Description           *string `json:"description"`
	AccessTokenExpiresIn  *int    `json:"access_token_expires_in"`
	RefreshTokenExpiresIn *int    `json:"refresh_token_expires_in"`
	Status                *int8   `json:"status"`
}

// ApplicationCreateRequest 创建应用请求
type ApplicationCreateRequest struct {
	DomainID     string   `json:"domain_id" binding:"required"`
	AppID        string   `json:"app_id" binding:"required"`
	Name         string   `json:"name" binding:"required"`
	RedirectURIs []string `json:"redirect_uris"`
	NeedKey      bool     `json:"need_key"` // 是否需要密钥
}

// ApplicationUpdateRequest 更新应用请求
type ApplicationUpdateRequest struct {
	Name         *string  `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// ApplicationServiceRelationRequest 应用服务关系请求
type ApplicationServiceRelationRequest struct {
	AppID     string   `json:"app_id" binding:"required"`
	ServiceID string   `json:"service_id" binding:"required"`
	Relations []string `json:"relations" binding:"required"` // 关系列表，["*"] 表示全部
}

// RelationshipCreateRequest 创建关系请求
type RelationshipCreateRequest struct {
	ServiceID   string  `json:"service_id" binding:"required"`
	SubjectType string  `json:"subject_type" binding:"required"` // user/group/application
	SubjectID   string  `json:"subject_id" binding:"required"`
	Relation    string  `json:"relation" binding:"required"`
	ObjectType  string  `json:"object_type" binding:"required"`
	ObjectID    string  `json:"object_id" binding:"required"`
	ExpiresAt   *string `json:"expires_at"` // ISO 8601 格式
}

// RelationshipDeleteRequest 删除关系请求
type RelationshipDeleteRequest struct {
	ServiceID   string `json:"service_id" binding:"required"`
	SubjectType string `json:"subject_type" binding:"required"`
	SubjectID   string `json:"subject_id" binding:"required"`
	Relation    string `json:"relation" binding:"required"`
	ObjectType  string `json:"object_type" binding:"required"`
	ObjectID    string `json:"object_id" binding:"required"`
}

// RelationshipUpdateRequest 更新关系请求
type RelationshipUpdateRequest struct {
	ServiceID   string  `json:"service_id" binding:"required"`
	SubjectType string  `json:"subject_type" binding:"required"`
	SubjectID   string  `json:"subject_id" binding:"required"`
	Relation    string  `json:"relation" binding:"required"` // 旧的关系类型（用于定位）
	ObjectType  string  `json:"object_type" binding:"required"`
	ObjectID    string  `json:"object_id" binding:"required"`
	NewRelation *string `json:"new_relation,omitempty"` // 新的关系类型（可选）
	ExpiresAt   *string `json:"expires_at,omitempty"`   // 新的过期时间（可选，ISO 8601 格式，传 null 表示清除过期时间）
}

// AppServiceRelationshipCreateRequest 在应用服务下创建关系请求（RESTful 风格）
type AppServiceRelationshipCreateRequest struct {
	SubjectType string  `json:"subject_type" binding:"required"` // user/group/application
	SubjectID   string  `json:"subject_id" binding:"required"`
	Relation    string  `json:"relation" binding:"required"`
	ObjectType  string  `json:"object_type" binding:"required"`
	ObjectID    string  `json:"object_id" binding:"required"`
	ExpiresAt   *string `json:"expires_at,omitempty"` // ISO 8601 格式
}

// AppServiceRelationshipUpdateRequest 在应用服务下更新关系请求（RESTful 风格）
type AppServiceRelationshipUpdateRequest struct {
	NewRelation *string `json:"new_relation,omitempty"` // 新的关系类型（可选）
	ExpiresAt   *string `json:"expires_at,omitempty"`   // 新的过期时间（可选，ISO 8601 格式，传空字符串表示清除过期时间）
}

// GroupCreateRequest 创建组请求
type GroupCreateRequest struct {
	GroupID     string  `json:"group_id" binding:"required"`
	Name        string  `json:"name" binding:"required"`
	Description *string `json:"description"`
}

// GroupUpdateRequest 更新组请求
type GroupUpdateRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

// GroupMemberRequest 组成员请求
type GroupMemberRequest struct {
	GroupID string   `json:"group_id" binding:"required"`
	UserIDs []string `json:"user_ids" binding:"required"`
}
