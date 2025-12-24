package com.security.model;

import com.google.gson.annotations.SerializedName;

public class OsVuln {
    public String id;
    public String summary;
    @SerializedName("severity")
    public OsSeverity severityData;
}