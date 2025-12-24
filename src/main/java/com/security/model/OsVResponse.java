package com.security.model;

import com.google.gson.annotations.SerializedName;
import java.util.List;

public class OsVResponse {
    @SerializedName("vulns")
    public List<OsVuln> vulns;
}