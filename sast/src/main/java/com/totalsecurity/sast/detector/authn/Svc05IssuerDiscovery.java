package com.totalsecurity.sast.detector.authn;

import com.totalsecurity.sast.interprocedural.ProjectClassEntry;
import com.totalsecurity.sast.interprocedural.ProjectClassIndex;
import com.totalsecurity.sast.ir.JavaFileInfo;
import com.totalsecurity.sast.ir.MethodInfo;
import com.totalsecurity.sast.ir.MethodKind;
import com.totalsecurity.sast.ir.TypeKind;
import com.totalsecurity.sast.rule.context.LightweightTypeContext;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/** Discovers source-declared JWT issuer return shapes without backend FQN special cases. */
final class Svc05IssuerDiscovery {
    IssuerTypes discover(Collection<JavaFileInfo> files) {
        ProjectClassIndex index = new ProjectClassIndex(files);
        LinkedHashSet<DirectIssuerMethod> directStringMethods = new LinkedHashSet<>();
        LinkedHashSet<DirectIssuerMethod> issuedRecordMethods = new LinkedHashSet<>();
        LinkedHashSet<String> issuedTokenRecords = new LinkedHashSet<>();
        for (ProjectClassEntry owner : index.uniqueClasses()) {
            if (!Authn11Names.simpleName(owner.qualifiedName()).equals("JwtTokenProvider")) {
                continue;
            }
            LightweightTypeContext types = new LightweightTypeContext(
                    owner.file(), index, owner.type());
            for (MethodInfo method : owner.type().methods()) {
                if (method.kind() != MethodKind.METHOD
                        || !(method.name().equals("issueAccessToken")
                                || method.name().equals("issueRefreshToken"))
                        || !uniqueNameAndArity(owner, method)) {
                    continue;
                }
                Optional<String> returnType = method.returnType().flatMap(types::qualifyTypeShape);
                if (returnType.filter("java.lang.String"::equals).isPresent()) {
                    directStringMethods.add(new DirectIssuerMethod(
                            owner.qualifiedName(), method.name(), method.parameters().size()));
                    continue;
                }
                returnType.flatMap(index::uniqueClass)
                        .filter(result -> exactTokenRecord(result, index))
                        .ifPresent(result -> {
                            issuedRecordMethods.add(new DirectIssuerMethod(
                                    owner.qualifiedName(), method.name(),
                                    method.parameters().size()));
                            issuedTokenRecords.add(result.qualifiedName());
                        });
            }
        }
        return new IssuerTypes(
                Set.copyOf(directStringMethods),
                Set.copyOf(issuedRecordMethods),
                Set.copyOf(issuedTokenRecords));
    }

    private static boolean uniqueNameAndArity(ProjectClassEntry owner, MethodInfo method) {
        return owner.type().methods().stream()
                .filter(candidate -> candidate.kind() == MethodKind.METHOD)
                .filter(candidate -> candidate.name().equals(method.name()))
                .filter(candidate -> candidate.parameters().size() == method.parameters().size())
                .count() == 1;
    }

    private static boolean exactTokenRecord(ProjectClassEntry result, ProjectClassIndex index) {
        if (result.type().kind() != TypeKind.RECORD) {
            return false;
        }
        LightweightTypeContext types = new LightweightTypeContext(
                result.file(), index, result.type());
        return result.type().recordComponents().stream()
                .filter(component -> component.name().equals("token"))
                .filter(component -> types.qualifyTypeShape(component.declaredType())
                        .filter("java.lang.String"::equals).isPresent())
                .count() == 1;
    }

    record DirectIssuerMethod(String owner, String methodName, int arity) {}

    record IssuerTypes(
            Set<DirectIssuerMethod> directStringMethods,
            Set<DirectIssuerMethod> issuedRecordMethods,
            Set<String> issuedTokenRecords) {
        IssuerTypes {
            directStringMethods = Set.copyOf(directStringMethods);
            issuedRecordMethods = Set.copyOf(issuedRecordMethods);
            issuedTokenRecords = Set.copyOf(issuedTokenRecords);
        }
    }
}
