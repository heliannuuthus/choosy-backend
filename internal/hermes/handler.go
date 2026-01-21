package hermes

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// Handler 管理服务处理器
type Handler struct {
	service *Service
}

// NewHandler 创建管理服务处理器
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// ==================== Domain 相关 ====================

// GetDomain GET /hermes/domains/:domain_id
func (h *Handler) GetDomain(c *gin.Context) {
	domainID := c.Param("domain_id")
	domain, err := h.service.GetDomain(c.Request.Context(), domainID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, domain)
}

// ListDomains GET /hermes/domains
func (h *Handler) ListDomains(c *gin.Context) {
	domains, err := h.service.ListDomains(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, domains)
}

// ==================== Service 相关 ====================

// CreateService POST /hermes/services
func (h *Handler) CreateService(c *gin.Context) {
	var req ServiceCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	service, err := h.service.CreateService(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 不返回加密密钥
	service.EncryptedKey = ""
	c.JSON(http.StatusOK, service)
}

// GetService GET /hermes/services/:service_id
func (h *Handler) GetService(c *gin.Context) {
	serviceID := c.Param("service_id")
	service, err := h.service.GetService(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// 不返回加密密钥
	service.EncryptedKey = ""
	c.JSON(http.StatusOK, service)
}

// ListServices GET /hermes/services
func (h *Handler) ListServices(c *gin.Context) {
	domainID := c.Query("domain_id")
	services, err := h.service.ListServices(c.Request.Context(), domainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 不返回加密密钥
	for i := range services {
		services[i].EncryptedKey = ""
	}
	c.JSON(http.StatusOK, services)
}

// UpdateService PUT /hermes/services/:service_id
func (h *Handler) UpdateService(c *gin.Context) {
	serviceID := c.Param("service_id")
	var req ServiceUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.UpdateService(c.Request.Context(), serviceID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// ==================== Application 相关 ====================

// CreateApplication POST /hermes/applications
func (h *Handler) CreateApplication(c *gin.Context) {
	var req ApplicationCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	app, err := h.service.CreateApplication(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 不返回加密密钥
	app.EncryptedKey = nil
	c.JSON(http.StatusOK, app)
}

// GetApplication GET /hermes/applications/:app_id
func (h *Handler) GetApplication(c *gin.Context) {
	appID := c.Param("app_id")
	app, err := h.service.GetApplication(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// 不返回加密密钥
	app.EncryptedKey = nil
	c.JSON(http.StatusOK, app)
}

// ListApplications GET /hermes/applications
func (h *Handler) ListApplications(c *gin.Context) {
	domainID := c.Query("domain_id")
	apps, err := h.service.ListApplications(c.Request.Context(), domainID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 不返回加密密钥
	for i := range apps {
		apps[i].EncryptedKey = nil
	}
	c.JSON(http.StatusOK, apps)
}

// UpdateApplication PUT /hermes/applications/:app_id
func (h *Handler) UpdateApplication(c *gin.Context) {
	appID := c.Param("app_id")
	var req ApplicationUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.UpdateApplication(c.Request.Context(), appID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// SetApplicationServiceRelations POST /hermes/applications/:app_id/services/:service_id/applicable
func (h *Handler) SetApplicationServiceRelations(c *gin.Context) {
	appID := c.Param("app_id")
	serviceID := c.Param("service_id")

	var req ApplicationServiceRelationRequest
	req.AppID = appID
	req.ServiceID = serviceID
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.SetApplicationServiceRelations(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "设置成功"})
}

// GetApplicationServiceRelations GET /hermes/applications/:app_id/applicable
func (h *Handler) GetApplicationServiceRelations(c *gin.Context) {
	appID := c.Param("app_id")
	relations, err := h.service.GetApplicationServiceRelations(c.Request.Context(), appID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, relations)
}

// ==================== Relationship 相关 ====================

// CreateRelationship POST /hermes/relationships
func (h *Handler) CreateRelationship(c *gin.Context) {
	var req RelationshipCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.CreateRelationship(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, rel)
}

// DeleteRelationship DELETE /hermes/relationships
func (h *Handler) DeleteRelationship(c *gin.Context) {
	var req RelationshipDeleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.DeleteRelationship(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// ListRelationships GET /hermes/relationships
func (h *Handler) ListRelationships(c *gin.Context) {
	serviceID := c.Query("service_id")
	subjectType := c.Query("subject_type")
	subjectID := c.Query("subject_id")

	rels, err := h.service.ListRelationships(c.Request.Context(), serviceID, subjectType, subjectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, rels)
}

// UpdateRelationship PUT /hermes/relationships
func (h *Handler) UpdateRelationship(c *gin.Context) {
	var req RelationshipUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.UpdateRelationship(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, rel)
}

// ==================== App Service Relationship 相关（RESTful 风格）====================

// ListAppServiceRelationships GET /hermes/applications/:app_id/services/:service_id/relationships
func (h *Handler) ListAppServiceRelationships(c *gin.Context) {
	appID := c.Param("app_id")
	serviceID := c.Param("service_id")
	subjectType := c.Query("subject_type")
	subjectID := c.Query("subject_id")

	rels, err := h.service.ListAppServiceRelationships(c.Request.Context(), appID, serviceID, subjectType, subjectID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, rels)
}

// CreateAppServiceRelationship POST /hermes/applications/:app_id/services/:service_id/relationships
func (h *Handler) CreateAppServiceRelationship(c *gin.Context) {
	appID := c.Param("app_id")
	serviceID := c.Param("service_id")

	var req AppServiceRelationshipCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.CreateAppServiceRelationship(c.Request.Context(), appID, serviceID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, rel)
}

// UpdateAppServiceRelationship PUT /hermes/applications/:app_id/services/:service_id/relationships/:relationship_id
func (h *Handler) UpdateAppServiceRelationship(c *gin.Context) {
	appID := c.Param("app_id")
	serviceID := c.Param("service_id")
	relationshipIDStr := c.Param("relationship_id")

	relationshipID, err := strconv.ParseUint(relationshipIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid relationship_id"})
		return
	}

	var req AppServiceRelationshipUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	rel, err := h.service.UpdateAppServiceRelationship(c.Request.Context(), appID, serviceID, uint(relationshipID), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, rel)
}

// DeleteAppServiceRelationship DELETE /hermes/applications/:app_id/services/:service_id/relationships/:relationship_id
func (h *Handler) DeleteAppServiceRelationship(c *gin.Context) {
	appID := c.Param("app_id")
	serviceID := c.Param("service_id")
	relationshipIDStr := c.Param("relationship_id")

	relationshipID, err := strconv.ParseUint(relationshipIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid relationship_id"})
		return
	}

	if err := h.service.DeleteAppServiceRelationship(c.Request.Context(), appID, serviceID, uint(relationshipID)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// ==================== Group 相关 ====================

// CreateGroup POST /hermes/groups
func (h *Handler) CreateGroup(c *gin.Context) {
	var req GroupCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	group, err := h.service.CreateGroup(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, group)
}

// GetGroup GET /hermes/groups/:group_id
func (h *Handler) GetGroup(c *gin.Context) {
	groupID := c.Param("group_id")
	group, err := h.service.GetGroup(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, group)
}

// ListGroups GET /hermes/groups
func (h *Handler) ListGroups(c *gin.Context) {
	groups, err := h.service.ListGroups(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, groups)
}

// UpdateGroup PUT /hermes/groups/:group_id
func (h *Handler) UpdateGroup(c *gin.Context) {
	groupID := c.Param("group_id")
	var req GroupUpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.UpdateGroup(c.Request.Context(), groupID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// SetGroupMembers POST /hermes/groups/:group_id/members
func (h *Handler) SetGroupMembers(c *gin.Context) {
	groupID := c.Param("group_id")
	var req GroupMemberRequest
	req.GroupID = groupID
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.SetGroupMembers(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "设置成功"})
}

// GetGroupMembers GET /hermes/groups/:group_id/members
func (h *Handler) GetGroupMembers(c *gin.Context) {
	groupID := c.Param("group_id")
	members, err := h.service.GetGroupMembers(c.Request.Context(), groupID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"members": members})
}
