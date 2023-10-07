package io.servertap.api.v1;

import io.javalin.http.Context;
import io.javalin.openapi.*;
import io.servertap.api.v1.models.Advancement;
import org.bukkit.Bukkit;

import java.util.ArrayList;

public class AdvancementsApi {
    @OpenApi(
            path = "/v1/advancements",
            summary = "Gets all server advancements",
            tags = {"Advancement"},
            security = @OpenApiSecurity(
                    name = "BearerAuth"
            ),
            responses = {
                    @OpenApiResponse(status = "200", content = @OpenApiContent(from = Advancement.class))
            }
    )
    public void getAdvancements(Context ctx) {
        final ArrayList<Advancement> advancements = new ArrayList<>();

        Bukkit.advancementIterator().forEachRemaining(advancement -> {
            Advancement a = new Advancement();
            a.setName(advancement.getKey().getKey());
            a.setCriteria(advancement.getCriteria().stream().toList());
            advancements.add(a);
        });

        ctx.json(advancements);
    }

}