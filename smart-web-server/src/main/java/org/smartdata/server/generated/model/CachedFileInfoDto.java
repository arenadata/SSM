package org.smartdata.server.generated.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Objects;
import javax.annotation.Generated;
import javax.validation.constraints.NotNull;

/**
 * CachedFileInfoDto
 */

@JsonTypeName("CachedFileInfo")
@Generated(value = "org.openapitools.codegen.languages.SpringCodegen")
public class CachedFileInfoDto {

  private Long id;

  private String path;

  private Integer accessCount;

  private Integer cachedTime;

  private Integer lastAccessTime;

  public CachedFileInfoDto() {
    super();
  }

  /**
   * Constructor with only required parameters
   */
  public CachedFileInfoDto(Long id, String path, Integer accessCount, Integer cachedTime, Integer lastAccessTime) {
    this.id = id;
    this.path = path;
    this.accessCount = accessCount;
    this.cachedTime = cachedTime;
    this.lastAccessTime = lastAccessTime;
  }

  public CachedFileInfoDto id(Long id) {
    this.id = id;
    return this;
  }

  /**
   * Id of the file
   * @return id
  */
  @NotNull 
  @Schema(name = "id", description = "Id of the file", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("id")
  public Long getId() {
    return id;
  }

  public void setId(Long id) {
    this.id = id;
  }

  public CachedFileInfoDto path(String path) {
    this.path = path;
    return this;
  }

  /**
   * Path of the file
   * @return path
  */
  @NotNull 
  @Schema(name = "path", description = "Path of the file", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("path")
  public String getPath() {
    return path;
  }

  public void setPath(String path) {
    this.path = path;
  }

  public CachedFileInfoDto accessCount(Integer accessCount) {
    this.accessCount = accessCount;
    return this;
  }

  /**
   * Number of accesses to the file
   * @return accessCount
  */
  @NotNull 
  @Schema(name = "accessCount", description = "Number of accesses to the file", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("accessCount")
  public Integer getAccessCount() {
    return accessCount;
  }

  public void setAccessCount(Integer accessCount) {
    this.accessCount = accessCount;
  }

  public CachedFileInfoDto cachedTime(Integer cachedTime) {
    this.cachedTime = cachedTime;
    return this;
  }

  /**
   * UNIX timestamp (UTC) when the file was cached
   * @return cachedTime
  */
  @NotNull 
  @Schema(name = "cachedTime", description = "UNIX timestamp (UTC) when the file was cached", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("cachedTime")
  public Integer getCachedTime() {
    return cachedTime;
  }

  public void setCachedTime(Integer cachedTime) {
    this.cachedTime = cachedTime;
  }

  public CachedFileInfoDto lastAccessTime(Integer lastAccessTime) {
    this.lastAccessTime = lastAccessTime;
    return this;
  }

  /**
   * UNIX timestamp (UTC) of the last file access
   * @return lastAccessTime
  */
  @NotNull 
  @Schema(name = "lastAccessTime", description = "UNIX timestamp (UTC) of the last file access", requiredMode = Schema.RequiredMode.REQUIRED)
  @JsonProperty("lastAccessTime")
  public Integer getLastAccessTime() {
    return lastAccessTime;
  }

  public void setLastAccessTime(Integer lastAccessTime) {
    this.lastAccessTime = lastAccessTime;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    CachedFileInfoDto cachedFileInfo = (CachedFileInfoDto) o;
    return Objects.equals(this.id, cachedFileInfo.id) &&
        Objects.equals(this.path, cachedFileInfo.path) &&
        Objects.equals(this.accessCount, cachedFileInfo.accessCount) &&
        Objects.equals(this.cachedTime, cachedFileInfo.cachedTime) &&
        Objects.equals(this.lastAccessTime, cachedFileInfo.lastAccessTime);
  }

  @Override
  public int hashCode() {
    return Objects.hash(id, path, accessCount, cachedTime, lastAccessTime);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class CachedFileInfoDto {\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    path: ").append(toIndentedString(path)).append("\n");
    sb.append("    accessCount: ").append(toIndentedString(accessCount)).append("\n");
    sb.append("    cachedTime: ").append(toIndentedString(cachedTime)).append("\n");
    sb.append("    lastAccessTime: ").append(toIndentedString(lastAccessTime)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
}
