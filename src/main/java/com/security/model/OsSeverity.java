package com.security.model;

import com.google.gson.annotations.SerializedName;
import java.util.List;

public class OsSeverity {
    @SerializedName("CVSSv3")
    public List<OsCvss> cvssV3Score;  // ← ARRAY, not single object
}